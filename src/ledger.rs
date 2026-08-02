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
        Ok(())
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
