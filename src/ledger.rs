//! The spend ledger: a durable SQLite record of every signature this service has produced,
//! used to enforce the rolling day/week/month spend limits in `policy.rs` and to make
//! `/sign_psbt` idempotent (each transaction is keyed by its unsigned txid, which is stable
//! across however many parties sign it - segwit txids never depend on witness data).
//!
//! This module owns all SQL. The policy engine never touches the database directly - it
//! consumes a plain [`RollingTotals`] snapshot, so it stays a pure function that can be
//! tested exhaustively without a database.
//!
//! [`LedgerTx`] is the atomic unit `/sign_psbt` needs: check idempotency, read rolling totals,
//! and (if approved) record the new spend, all inside one SQLite transaction. SQLite only
//! allows one writer at a time, so holding a transaction open across that whole sequence is
//! what makes concurrent requests serialize correctly against the same rolling-limit budget
//! instead of racing past it.

use anyhow::{Context, Result};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use sqlx::{Sqlite, Transaction};

pub const DAY_SECONDS: i64 = 24 * 60 * 60;
pub const WEEK_SECONDS: i64 = 7 * DAY_SECONDS;
pub const MONTH_SECONDS: i64 = 30 * DAY_SECONDS;

/// Sums of past spends within trailing windows ending "now" - the only thing the policy
/// engine needs to know about the ledger.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RollingTotals {
    pub day_sat: u64,
    pub week_sat: u64,
    pub month_sat: u64,
}

/// Where a submitted-and-approved spend sits in the M5 notify-then-hold-then-sign queue.
/// `Pending` is the only non-terminal state; every other value is reached exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingStatus {
    /// Notified, holding, not yet due (or due but not yet swept).
    Pending,
    /// A human called `POST /veto/{id}` before the hold elapsed - permanently blocked.
    Vetoed,
    /// The hold elapsed and it was signed and recorded in `ledger`.
    Signed,
    /// The hold elapsed but policy no longer allows it (rolling totals moved since
    /// submission) - never signed, nothing recorded.
    Denied,
    /// The hold elapsed but signing/inspection failed for a reason other than policy (e.g.
    /// the UTXO it spent is gone) - never signed, nothing recorded.
    Failed,
}

impl PendingStatus {
    fn as_str(self) -> &'static str {
        match self {
            PendingStatus::Pending => "pending",
            PendingStatus::Vetoed => "vetoed",
            PendingStatus::Signed => "signed",
            PendingStatus::Denied => "denied",
            PendingStatus::Failed => "failed",
        }
    }

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "pending" => Ok(PendingStatus::Pending),
            "vetoed" => Ok(PendingStatus::Vetoed),
            "signed" => Ok(PendingStatus::Signed),
            "denied" => Ok(PendingStatus::Denied),
            "failed" => Ok(PendingStatus::Failed),
            other => anyhow::bail!("unrecognized pending_signatures.status value {other:?}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PendingRow {
    pub txid: String,
    pub psbt_base64: String,
    pub spend_amount_sat: u64,
    pub fee_sat: u64,
    pub created_at: i64,
    pub hold_until: i64,
    pub status: PendingStatus,
    pub signed_psbt_base64: Option<String>,
    pub message: Option<String>,
}

pub struct Ledger {
    pool: SqlitePool,
}

impl Ledger {
    /// Opens (creating if needed) a SQLite database file at `path`.
    ///
    /// Deliberately a single-connection pool: SQLite only ever allows one writer at a time
    /// regardless, but a plain (`DEFERRED`) transaction only acquires SQLite's write lock at
    /// its *first write*, not at `BEGIN` - so with more than one connection, two concurrent
    /// `LedgerTx`s could both read `rolling_totals()` before either has written anything, both
    /// decide a spend is within budget, and both then successfully commit, together blowing
    /// past a rolling cap neither alone would have. Capping the pool at one connection makes
    /// that interleaving impossible: a second `begin()` simply waits for the first `LedgerTx`
    /// to be dropped (commit, rollback, or dropped uncommitted) before it can start, so its
    /// own read of `rolling_totals()` is always guaranteed to already reflect the first one's
    /// outcome.
    pub async fn connect(path: &str) -> Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&format!("sqlite://{path}?mode=rwc"))
            .await
            .with_context(|| format!("opening ledger database at {path}"))?;
        let ledger = Self { pool };
        ledger.migrate().await?;
        Ok(ledger)
    }

    /// An ephemeral in-memory database - for tests only. Also single-connection: an in-memory
    /// SQLite database is private to the connection that created it, so a second connection
    /// would see an entirely separate, empty database rather than sharing this one.
    pub async fn connect_in_memory() -> Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .context("opening in-memory ledger database")?;
        let ledger = Self { pool };
        ledger.migrate().await?;
        Ok(ledger)
    }

    async fn migrate(&self) -> Result<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                txid TEXT NOT NULL UNIQUE,
                recorded_at INTEGER NOT NULL,
                spend_amount_sat INTEGER NOT NULL,
                fee_sat INTEGER NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .context("creating ledger table")?;

        // The M5 notify-then-hold-then-sign queue. One row per unsigned txid ever submitted
        // to `/sign_psbt` and approved at submission time; `status` tracks it from `pending`
        // to exactly one terminal state (`signed`, `vetoed`, `denied`, or `failed`). Lives in
        // the same single-connection pool as `ledger` so the sweeper's fire-time processing,
        // `POST /veto/{id}`, and a fresh `/sign_psbt` submission all serialize against each
        // other automatically - no separate locking needed.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS pending_signatures (
                txid TEXT PRIMARY KEY,
                psbt_base64 TEXT NOT NULL,
                spend_amount_sat INTEGER NOT NULL,
                fee_sat INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                hold_until INTEGER NOT NULL,
                status TEXT NOT NULL,
                signed_psbt_base64 TEXT,
                message TEXT
            )",
        )
        .execute(&self.pool)
        .await
        .context("creating pending_signatures table")?;
        Ok(())
    }

    /// txids of every `pending`-status row whose hold has elapsed as of `now` - what the
    /// background sweeper should attempt to process next. A plain pool read: each row gets
    /// re-checked for its current status inside its own transaction when actually processed,
    /// so a stale read here (e.g. a veto racing in after this query) is always caught later.
    pub async fn due_pending(&self, now: i64) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT txid FROM pending_signatures WHERE status = ?1 AND hold_until <= ?2",
        )
        .bind(PendingStatus::Pending.as_str())
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .context("querying due pending signatures")?;
        Ok(rows.into_iter().map(|(txid,)| txid).collect())
    }

    /// Marks a `pending` row `vetoed`, atomically (only transitions rows still `pending`).
    /// Returns the row's status *after* the attempt, so the caller can distinguish "vetoed
    /// just now" from "was already something else" without a second query.
    pub async fn veto_pending(&self, txid: &str) -> Result<Option<PendingStatus>> {
        let mut ltx = self.begin().await?;
        let Some(row) = ltx.get_pending(txid).await? else {
            ltx.rollback().await?;
            return Ok(None);
        };
        if row.status == PendingStatus::Pending {
            ltx.mark_pending_vetoed(txid).await?;
            ltx.commit().await?;
            Ok(Some(PendingStatus::Vetoed))
        } else {
            ltx.rollback().await?;
            Ok(Some(row.status))
        }
    }

    pub async fn get_pending(&self, txid: &str) -> Result<Option<PendingRow>> {
        let mut ltx = self.begin().await?;
        let row = ltx.get_pending(txid).await?;
        ltx.rollback().await?;
        Ok(row)
    }

    /// Sums `spend_amount_sat` over the trailing day/week/month windows ending at `now`.
    /// A plain, non-transactional read - for reporting. `/sign_psbt` uses
    /// [`LedgerTx::rolling_totals`] instead, so its read is part of the same atomic
    /// check-then-record sequence.
    pub async fn rolling_totals(&self, now: i64) -> Result<RollingTotals> {
        rolling_totals_via(&self.pool, now).await
    }

    /// Records a spend outside of the atomic `/sign_psbt` flow (tests, backfills). Fails if
    /// `txid` was already recorded (`UNIQUE` constraint) - for the idempotent-or-deny flow
    /// `/sign_psbt` actually needs, use [`Ledger::begin`] instead.
    pub async fn record_spend(
        &self,
        txid: &str,
        recorded_at: i64,
        spend_amount_sat: u64,
        fee_sat: u64,
    ) -> Result<()> {
        let mut tx = self.begin().await?;
        tx.record_spend(txid, recorded_at, spend_amount_sat, fee_sat)
            .await?;
        tx.commit().await
    }

    /// Starts a transaction for an atomic idempotency-check + policy-evaluate + record
    /// sequence. See [`LedgerTx`].
    pub async fn begin(&self) -> Result<LedgerTx> {
        let tx = self
            .pool
            .begin()
            .await
            .context("beginning ledger transaction")?;
        Ok(LedgerTx { tx })
    }
}

async fn rolling_totals_via<'e, E>(executor: E, now: i64) -> Result<RollingTotals>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let rows: Vec<(i64, i64)> =
        sqlx::query_as("SELECT recorded_at, spend_amount_sat FROM ledger WHERE recorded_at > ?1")
            .bind(now - MONTH_SECONDS)
            .fetch_all(executor)
            .await
            .context("querying ledger for rolling totals")?;

    let mut totals = RollingTotals::default();
    for (recorded_at, amount_sat) in rows {
        let age = now - recorded_at;
        if age < 0 {
            continue; // future-dated entry (clock skew, bad data): ignore defensively
        }
        let amount_sat = amount_sat as u64;
        if age < DAY_SECONDS {
            totals.day_sat += amount_sat;
        }
        if age < WEEK_SECONDS {
            totals.week_sat += amount_sat;
        }
        if age < MONTH_SECONDS {
            totals.month_sat += amount_sat;
        }
    }
    Ok(totals)
}

/// A held SQLite transaction wrapping the ledger table. Dropping this without calling
/// [`commit`](LedgerTx::commit) rolls back automatically (sqlx's `Transaction` does this on
/// `Drop`), so an early return via `?` anywhere in a `/sign_psbt` handler safely discards any
/// uncommitted work - nothing is recorded unless `commit()` is reached.
pub struct LedgerTx {
    tx: Transaction<'static, Sqlite>,
}

impl LedgerTx {
    /// Whether `txid` has already been recorded - the idempotency check. If this is true,
    /// `/sign_psbt` must not evaluate policy or record again; it should still re-sign and
    /// return the PSBT (ECDSA signing is deterministic, so this is a safe, cheap replay).
    pub async fn already_recorded(&mut self, txid: &str) -> Result<bool> {
        let row: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM ledger WHERE txid = ?1")
            .bind(txid)
            .fetch_optional(&mut *self.tx)
            .await
            .context("checking ledger for existing txid")?;
        Ok(row.is_some())
    }

    /// Rolling totals as seen from inside this transaction - i.e. including every spend a
    /// concurrent, already-committed transaction recorded, and none from one still in
    /// flight (SQLite's single-writer semantics mean at most one `LedgerTx` is ever mutating
    /// the table at a time).
    pub async fn rolling_totals(&mut self, now: i64) -> Result<RollingTotals> {
        rolling_totals_via(&mut *self.tx, now).await
    }

    pub async fn record_spend(
        &mut self,
        txid: &str,
        recorded_at: i64,
        spend_amount_sat: u64,
        fee_sat: u64,
    ) -> Result<()> {
        sqlx::query("INSERT INTO ledger (txid, recorded_at, spend_amount_sat, fee_sat) VALUES (?1, ?2, ?3, ?4)")
            .bind(txid)
            .bind(recorded_at)
            .bind(spend_amount_sat as i64)
            .bind(fee_sat as i64)
            .execute(&mut *self.tx)
            .await
            .context("recording spend in ledger")?;
        Ok(())
    }

    /// Fails if `txid` already has a pending-signatures row (`PRIMARY KEY`) - callers must
    /// check [`get_pending`](Self::get_pending) first within the same transaction.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_pending(
        &mut self,
        txid: &str,
        psbt_base64: &str,
        spend_amount_sat: u64,
        fee_sat: u64,
        created_at: i64,
        hold_until: i64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO pending_signatures
                (txid, psbt_base64, spend_amount_sat, fee_sat, created_at, hold_until, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(txid)
        .bind(psbt_base64)
        .bind(spend_amount_sat as i64)
        .bind(fee_sat as i64)
        .bind(created_at)
        .bind(hold_until)
        .bind(PendingStatus::Pending.as_str())
        .execute(&mut *self.tx)
        .await
        .context("inserting pending signature request")?;
        Ok(())
    }

    pub async fn get_pending(&mut self, txid: &str) -> Result<Option<PendingRow>> {
        #[allow(clippy::type_complexity)]
        let row: Option<(
            String,
            String,
            i64,
            i64,
            i64,
            i64,
            String,
            Option<String>,
            Option<String>,
        )> = sqlx::query_as(
            "SELECT txid, psbt_base64, spend_amount_sat, fee_sat, created_at, hold_until, \
                    status, signed_psbt_base64, message
             FROM pending_signatures WHERE txid = ?1",
        )
        .bind(txid)
        .fetch_optional(&mut *self.tx)
        .await
        .context("querying pending signature request")?;

        row.map(
            |(
                txid,
                psbt_base64,
                spend_amount_sat,
                fee_sat,
                created_at,
                hold_until,
                status,
                signed_psbt_base64,
                message,
            )| {
                Ok(PendingRow {
                    txid,
                    psbt_base64,
                    spend_amount_sat: spend_amount_sat as u64,
                    fee_sat: fee_sat as u64,
                    created_at,
                    hold_until,
                    status: PendingStatus::from_str(&status)?,
                    signed_psbt_base64,
                    message,
                })
            },
        )
        .transpose()
    }

    async fn set_pending_status(
        &mut self,
        txid: &str,
        status: PendingStatus,
        signed_psbt_base64: Option<&str>,
        message: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE pending_signatures
             SET status = ?1, signed_psbt_base64 = ?2, message = ?3
             WHERE txid = ?4",
        )
        .bind(status.as_str())
        .bind(signed_psbt_base64)
        .bind(message)
        .bind(txid)
        .execute(&mut *self.tx)
        .await
        .context("updating pending signature request")?;
        Ok(())
    }

    pub async fn mark_pending_signed(
        &mut self,
        txid: &str,
        signed_psbt_base64: &str,
    ) -> Result<()> {
        self.set_pending_status(txid, PendingStatus::Signed, Some(signed_psbt_base64), None)
            .await
    }

    pub async fn mark_pending_denied(&mut self, txid: &str, message: &str) -> Result<()> {
        self.set_pending_status(txid, PendingStatus::Denied, None, Some(message))
            .await
    }

    pub async fn mark_pending_failed(&mut self, txid: &str, message: &str) -> Result<()> {
        self.set_pending_status(txid, PendingStatus::Failed, None, Some(message))
            .await
    }

    /// Only ever called on a row already confirmed `Pending` by the caller - see
    /// [`Ledger::veto_pending`], the sole entry point.
    async fn mark_pending_vetoed(&mut self, txid: &str) -> Result<()> {
        self.set_pending_status(txid, PendingStatus::Vetoed, None, None)
            .await
    }

    pub async fn commit(self) -> Result<()> {
        self.tx
            .commit()
            .await
            .context("committing ledger transaction")
    }

    pub async fn rollback(self) -> Result<()> {
        self.tx
            .rollback()
            .await
            .context("rolling back ledger transaction")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_ledger_has_zero_totals() {
        let ledger = Ledger::connect_in_memory().await.unwrap();
        let totals = ledger.rolling_totals(1_000_000).await.unwrap();
        assert_eq!(totals, RollingTotals::default());
    }

    #[tokio::test]
    async fn sums_entries_within_each_window() {
        let ledger = Ledger::connect_in_memory().await.unwrap();
        let now = 10 * MONTH_SECONDS; // comfortably away from 0 so "- WINDOW" never underflows

        ledger.record_spend("tx-a", now, 1_000, 10).await.unwrap(); // right now: in all windows
        ledger
            .record_spend("tx-b", now - DAY_SECONDS + 1, 2_000, 10)
            .await
            .unwrap(); // just inside the day window
        ledger
            .record_spend("tx-c", now - WEEK_SECONDS + 1, 4_000, 10)
            .await
            .unwrap(); // inside week, not day
        ledger
            .record_spend("tx-d", now - MONTH_SECONDS + 1, 8_000, 10)
            .await
            .unwrap(); // inside month, not week

        let totals = ledger.rolling_totals(now).await.unwrap();
        assert_eq!(totals.day_sat, 1_000 + 2_000);
        assert_eq!(totals.week_sat, 1_000 + 2_000 + 4_000);
        assert_eq!(totals.month_sat, 1_000 + 2_000 + 4_000 + 8_000);
    }

    /// Each window's boundary is exact and independent of the others: an entry exactly one
    /// window-length old is excluded from *that* window but still counts toward any larger
    /// window it's still within (e.g. exactly 1 day old still counts toward the week total).
    #[tokio::test]
    async fn window_boundaries_are_exact_and_independent() {
        async fn totals_for_age(age: i64) -> RollingTotals {
            let ledger = Ledger::connect_in_memory().await.unwrap();
            let now = 10 * MONTH_SECONDS;
            ledger
                .record_spend("tx", now - age, 1_000, 0)
                .await
                .unwrap();
            ledger.rolling_totals(now).await.unwrap()
        }

        // One second under each boundary: included in that window (and every larger one).
        assert_eq!(
            totals_for_age(DAY_SECONDS - 1).await,
            RollingTotals {
                day_sat: 1_000,
                week_sat: 1_000,
                month_sat: 1_000
            }
        );
        assert_eq!(
            totals_for_age(WEEK_SECONDS - 1).await,
            RollingTotals {
                day_sat: 0,
                week_sat: 1_000,
                month_sat: 1_000
            }
        );
        assert_eq!(
            totals_for_age(MONTH_SECONDS - 1).await,
            RollingTotals {
                day_sat: 0,
                week_sat: 0,
                month_sat: 1_000
            }
        );

        // Exactly on each boundary: excluded from that window, but still within any larger one.
        assert_eq!(
            totals_for_age(DAY_SECONDS).await,
            RollingTotals {
                day_sat: 0,
                week_sat: 1_000,
                month_sat: 1_000
            }
        );
        assert_eq!(
            totals_for_age(WEEK_SECONDS).await,
            RollingTotals {
                day_sat: 0,
                week_sat: 0,
                month_sat: 1_000
            }
        );
        assert_eq!(
            totals_for_age(MONTH_SECONDS).await,
            RollingTotals::default()
        );

        // Past the largest window entirely: excluded from everything.
        assert_eq!(
            totals_for_age(MONTH_SECONDS + 1).await,
            RollingTotals::default()
        );
    }

    #[tokio::test]
    async fn ignores_future_dated_entries() {
        let ledger = Ledger::connect_in_memory().await.unwrap();
        let now = 10 * MONTH_SECONDS;
        ledger
            .record_spend("tx", now + 100, 5_000, 0)
            .await
            .unwrap();
        let totals = ledger.rolling_totals(now).await.unwrap();
        assert_eq!(totals, RollingTotals::default());
    }

    #[tokio::test]
    async fn record_spend_rejects_a_duplicate_txid() {
        let ledger = Ledger::connect_in_memory().await.unwrap();
        ledger.record_spend("dup", 1_000, 1, 1).await.unwrap();
        assert!(ledger.record_spend("dup", 2_000, 1, 1).await.is_err());
    }

    #[tokio::test]
    async fn ledger_tx_already_recorded_reflects_committed_state() {
        let ledger = Ledger::connect_in_memory().await.unwrap();
        ledger.record_spend("committed", 1_000, 1, 1).await.unwrap();

        let mut tx = ledger.begin().await.unwrap();
        assert!(tx.already_recorded("committed").await.unwrap());
        assert!(!tx.already_recorded("never-seen").await.unwrap());
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn ledger_tx_dropped_without_commit_rolls_back() {
        let ledger = Ledger::connect_in_memory().await.unwrap();
        {
            let mut tx = ledger.begin().await.unwrap();
            tx.record_spend("abandoned", 1_000, 5_000, 0).await.unwrap();
            // `tx` dropped here without commit() or rollback() - must not persist.
        }
        assert!(!ledger
            .begin()
            .await
            .unwrap()
            .already_recorded("abandoned")
            .await
            .unwrap());
        assert_eq!(
            ledger.rolling_totals(10 * MONTH_SECONDS).await.unwrap(),
            RollingTotals::default()
        );
    }

    #[tokio::test]
    async fn pending_insert_get_and_due_roundtrip() {
        let ledger = Ledger::connect_in_memory().await.unwrap();
        let mut ltx = ledger.begin().await.unwrap();
        ltx.insert_pending("tx-a", "cHNidA==", 1_000, 100, 500, 800)
            .await
            .unwrap();
        ltx.commit().await.unwrap();

        let row = ledger.get_pending("tx-a").await.unwrap().unwrap();
        assert_eq!(row.status, PendingStatus::Pending);
        assert_eq!(row.spend_amount_sat, 1_000);
        assert_eq!(row.hold_until, 800);
        assert!(ledger.get_pending("never-seen").await.unwrap().is_none());

        assert!(ledger.due_pending(799).await.unwrap().is_empty());
        assert_eq!(ledger.due_pending(800).await.unwrap(), vec!["tx-a"]);
        assert_eq!(ledger.due_pending(801).await.unwrap(), vec!["tx-a"]);
    }

    #[tokio::test]
    async fn veto_pending_transitions_a_pending_row_and_is_reported_back() {
        let ledger = Ledger::connect_in_memory().await.unwrap();
        let mut ltx = ledger.begin().await.unwrap();
        ltx.insert_pending("tx-a", "cHNidA==", 1_000, 100, 500, 800)
            .await
            .unwrap();
        ltx.commit().await.unwrap();

        assert_eq!(
            ledger.veto_pending("tx-a").await.unwrap(),
            Some(PendingStatus::Vetoed)
        );
        assert_eq!(
            ledger.get_pending("tx-a").await.unwrap().unwrap().status,
            PendingStatus::Vetoed
        );
        // A due-pending sweep must never pick up a vetoed row.
        assert!(ledger.due_pending(1_000).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn veto_pending_on_unknown_txid_returns_none() {
        let ledger = Ledger::connect_in_memory().await.unwrap();
        assert_eq!(ledger.veto_pending("never-seen").await.unwrap(), None);
    }

    #[tokio::test]
    async fn veto_pending_is_a_no_op_on_an_already_terminal_row() {
        let ledger = Ledger::connect_in_memory().await.unwrap();
        let mut ltx = ledger.begin().await.unwrap();
        ltx.insert_pending("tx-a", "cHNidA==", 1_000, 100, 500, 800)
            .await
            .unwrap();
        ltx.mark_pending_signed("tx-a", "cHNidA==-signed")
            .await
            .unwrap();
        ltx.commit().await.unwrap();

        // Too late to veto - reports the actual (signed) status rather than pretending to
        // veto it, and must not overwrite `signed_psbt_base64`.
        assert_eq!(
            ledger.veto_pending("tx-a").await.unwrap(),
            Some(PendingStatus::Signed)
        );
        let row = ledger.get_pending("tx-a").await.unwrap().unwrap();
        assert_eq!(row.status, PendingStatus::Signed);
        assert_eq!(row.signed_psbt_base64.as_deref(), Some("cHNidA==-signed"));
    }

    #[tokio::test]
    async fn mark_pending_denied_and_failed_record_a_message() {
        let ledger = Ledger::connect_in_memory().await.unwrap();
        let mut ltx = ledger.begin().await.unwrap();
        ltx.insert_pending("tx-denied", "cHNidA==", 1_000, 100, 500, 800)
            .await
            .unwrap();
        ltx.mark_pending_denied("tx-denied", "over the daily cap")
            .await
            .unwrap();
        ltx.insert_pending("tx-failed", "cHNidA==", 1_000, 100, 500, 800)
            .await
            .unwrap();
        ltx.mark_pending_failed("tx-failed", "utxo no longer exists")
            .await
            .unwrap();
        ltx.commit().await.unwrap();

        let denied = ledger.get_pending("tx-denied").await.unwrap().unwrap();
        assert_eq!(denied.status, PendingStatus::Denied);
        assert_eq!(denied.message.as_deref(), Some("over the daily cap"));

        let failed = ledger.get_pending("tx-failed").await.unwrap().unwrap();
        assert_eq!(failed.status, PendingStatus::Failed);
        assert_eq!(failed.message.as_deref(), Some("utxo no longer exists"));
    }

    #[tokio::test]
    async fn ledger_tx_rolling_totals_sees_its_own_uncommitted_row() {
        // Reads inside a transaction see writes made earlier in that same transaction
        // (needed so /sign_psbt's "insert, then re-derive totals for the response" works).
        let ledger = Ledger::connect_in_memory().await.unwrap();
        let now = 10 * MONTH_SECONDS;
        let mut tx = ledger.begin().await.unwrap();
        tx.record_spend("self-visible", now, 4_242, 0)
            .await
            .unwrap();
        let totals = tx.rolling_totals(now).await.unwrap();
        assert_eq!(totals.day_sat, 4_242);
        tx.commit().await.unwrap();
    }
}
