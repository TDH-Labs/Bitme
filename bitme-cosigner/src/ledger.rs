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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyState {
    pub version: u64,
    pub policy_json: String,
    pub updated_at: i64,
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

        // The M6 runtime-mutable, HARDWARE-authorized policy: exactly one row (`id = 1`),
        // holding the currently-effective policy and a monotonic version number. A change is
        // only ever applied by `policy_auth::apply_policy_change`, which requires the request
        // to target `version + 1` - both preventing two racing changes from silently
        // clobbering each other, and preventing an old signed authorization from being
        // replayed later to roll back to a looser policy.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS policy_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                version INTEGER NOT NULL,
                policy_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .context("creating policy_state table")?;

        // The freeze kill-switch: a single row (`id = 1`) that, when set, makes this service
        // refuse to co-sign anything at all. Durable on purpose - a freeze must survive a
        // restart, or "turn it off and on again" would silently disarm it.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS freeze_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                frozen INTEGER NOT NULL,
                changed_at INTEGER NOT NULL,
                reason TEXT
            )",
        )
        .execute(&self.pool)
        .await
        .context("creating freeze_state table")?;

        // Added after the initial pending_signatures schema shipped, so it goes on as an ALTER
        // rather than a column in the CREATE above - existing databases must keep working.
        // SQLite has no `ADD COLUMN IF NOT EXISTS`; re-running it on a database that already
        // has the column errors, which is the expected steady state, so that one error is
        // swallowed and anything else propagates.
        let alter = sqlx::query(
            "ALTER TABLE pending_signatures ADD COLUMN last_notified_at INTEGER NOT NULL DEFAULT 0",
        )
        .execute(&self.pool)
        .await;
        match alter {
            Ok(_) => {}
            Err(e) if e.to_string().contains("duplicate column name") => {}
            Err(e) => return Err(anyhow::Error::new(e).context("adding last_notified_at column")),
        }

        // Whether a notification for this row was ever *confirmed delivered* - as opposed to
        // `last_notified_at`, which records when delivery was last *attempted*.
        //
        // **Invariant: a spend nobody was told about is never signed.** The distinction between
        // attempted and delivered is what enforces it. `insert_pending` has to commit the row
        // before the notification is sent, because sending is network I/O and must not be done
        // while holding a write transaction - so there is necessarily a window in which a
        // committed `pending` row exists that nobody has been told about. Anything that ends the
        // process, or leaves the send outstanding, lands in that window. `due_pending` requires
        // this flag, so such a row is held rather than signed on schedule, and the re-notify
        // sweeper keeps retrying until a notification actually lands.
        //
        // DEFAULT 1 deliberately: rows that already exist on upgrade predate the flag and were
        // notified under the old path, so they must not be stranded unsignable. Fresh inserts
        // bind 0 explicitly.
        let alter_delivered = sqlx::query(
            "ALTER TABLE pending_signatures ADD COLUMN notify_delivered INTEGER NOT NULL DEFAULT 1",
        )
        .execute(&self.pool)
        .await;
        match alter_delivered {
            Ok(_) => {}
            Err(e) if e.to_string().contains("duplicate column name") => {}
            Err(e) => return Err(anyhow::Error::new(e).context("adding notify_delivered column")),
        }

        // A counter that increments on every freeze (never on unfreeze), so an unfreeze
        // authorization signed for one freeze can never lift a *later* one - see
        // `policy_auth::canonical_unfreeze_message`. Existing rows backfill to 0 via the
        // column default, same idempotent-ALTER pattern as `last_notified_at` above.
        let alter_generation = sqlx::query(
            "ALTER TABLE freeze_state ADD COLUMN generation INTEGER NOT NULL DEFAULT 0",
        )
        .execute(&self.pool)
        .await;
        match alter_generation {
            Ok(_) => {}
            Err(e) if e.to_string().contains("duplicate column name") => {}
            Err(e) => return Err(anyhow::Error::new(e).context("adding generation column")),
        }

        // Every Nostr gift-wrap event this service has ever dispatched (see
        // `nostr_transport.rs`), by ID. Durable on purpose: relays don't guarantee at-most-once
        // delivery, and a fresh subscription (which every process restart creates) replays a
        // client's *entire* matching history from each relay - without this, an old captured
        // message (e.g. a since-superseded /unfreeze request) would silently re-fire on every
        // restart, with no attacker needed at all.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS nostr_seen_events (
                event_id TEXT PRIMARY KEY,
                seen_at INTEGER NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .context("creating nostr_seen_events table")?;

        Ok(())
    }

    /// Drops `nostr_seen_events` rows older than `cutoff`, returning how many went.
    ///
    /// Replay protection only has to outlast how far back a relay will resend on a fresh
    /// subscription; beyond that the row is dead weight. Without pruning this table grows
    /// without bound on a box that is expected to run for years, and every row is written in
    /// response to an inbound message - so its size is not governed by the operator.
    pub async fn prune_nostr_seen_events(&self, cutoff: i64) -> Result<u64> {
        let result = sqlx::query("DELETE FROM nostr_seen_events WHERE seen_at < ?1")
            .bind(cutoff)
            .execute(&self.pool)
            .await
            .context("pruning nostr_seen_events")?;
        Ok(result.rows_affected())
    }

    /// Pending rows that are still holding (not yet due) and haven't been notified about since
    /// `now - interval`. Reminding during the window is the difference between "you had a
    /// chance to veto" and "you missed the one notification and never knew" - Bitkey pings
    /// repeatedly across its delay window for exactly this reason.
    pub async fn pending_needing_renotify(
        &self,
        now: i64,
        interval_seconds: i64,
    ) -> Result<Vec<PendingRow>> {
        // `hold_until > now` normally stops reminders once the window closes - past that point
        // the row is about to be signed and a reminder is pointless. The `notify_delivered = 0`
        // arm deliberately overrides that: a row nobody was ever told about is held back from
        // signing indefinitely, so it must keep being retried past its hold or it stalls
        // forever with no further attempt to reach anyone.
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT txid FROM pending_signatures
             WHERE status = ?1
               AND (hold_until > ?2 OR notify_delivered = 0)
               AND last_notified_at <= ?3",
        )
        .bind(PendingStatus::Pending.as_str())
        .bind(now)
        .bind(now - interval_seconds)
        .fetch_all(&self.pool)
        .await
        .context("querying pending rows needing re-notification")?;

        let mut out = Vec::new();
        for (txid,) in rows {
            if let Some(row) = self.get_pending(&txid).await? {
                out.push(row);
            }
        }
        Ok(out)
    }

    /// Records that a notification for `txid` was **confirmed delivered** - the notifier
    /// returned success, not merely that a send was attempted. This is what releases the row to
    /// [`Self::due_pending`], so it must only ever be called after a successful `notify()`.
    pub async fn mark_notified(&self, txid: &str, at: i64) -> Result<()> {
        sqlx::query(
            "UPDATE pending_signatures SET last_notified_at = ?1, notify_delivered = 1
             WHERE txid = ?2",
        )
        .bind(at)
        .bind(txid)
        .execute(&self.pool)
        .await
        .context("updating last_notified_at")?;
        Ok(())
    }

    /// Whether signing is currently frozen. Absent row = not frozen.
    pub async fn is_frozen(&self) -> Result<bool> {
        let row: Option<(i64,)> = sqlx::query_as("SELECT frozen FROM freeze_state WHERE id = 1")
            .fetch_optional(&self.pool)
            .await
            .context("querying freeze_state")?;
        Ok(row.is_some_and(|(f,)| f != 0))
    }

    /// Freezing bumps `generation`; unfreezing never does. Every distinct freeze event therefore
    /// gets a generation number no signed unfreeze authorization has ever targeted before -
    /// see `policy_auth::canonical_unfreeze_message`.
    pub async fn set_frozen(
        &self,
        frozen: bool,
        changed_at: i64,
        reason: Option<&str>,
    ) -> Result<()> {
        if frozen {
            sqlx::query(
                "INSERT INTO freeze_state (id, frozen, changed_at, reason, generation)
                 VALUES (1, 1, ?1, ?2, 1)
                 ON CONFLICT(id) DO UPDATE SET frozen = 1, changed_at = excluded.changed_at, \
                    reason = excluded.reason, generation = freeze_state.generation + 1",
            )
            .bind(changed_at)
            .bind(reason)
            .execute(&self.pool)
            .await
            .context("writing freeze_state")?;
        } else {
            // No ON CONFLICT needed: if no row exists yet, this affects zero rows, which is
            // correct - `is_frozen()` already treats an absent row as "not frozen".
            sqlx::query(
                "UPDATE freeze_state SET frozen = 0, changed_at = ?1, reason = ?2 WHERE id = 1",
            )
            .bind(changed_at)
            .bind(reason)
            .execute(&self.pool)
            .await
            .context("writing freeze_state")?;
        }
        Ok(())
    }

    /// The current freeze generation - 0 if this service has never been frozen. Used both to
    /// answer `GET /freeze` and to compute the exact text an unfreeze authorization must sign
    /// over (see `policy_auth::canonical_unfreeze_message`).
    pub async fn freeze_generation(&self) -> Result<u64> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT generation FROM freeze_state WHERE id = 1")
                .fetch_optional(&self.pool)
                .await
                .context("querying freeze_state generation")?;
        Ok(row.map(|(g,)| g as u64).unwrap_or(0))
    }

    /// Whether this exact Nostr gift-wrap event ID has already been dispatched - see
    /// `nostr_transport.rs`. Check this *before* unwrapping/dispatching a newly-received event,
    /// so a relay-replayed or restart-replayed event never fires twice.
    pub async fn has_seen_nostr_event(&self, event_id: &str) -> Result<bool> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT 1 FROM nostr_seen_events WHERE event_id = ?1")
                .bind(event_id)
                .fetch_optional(&self.pool)
                .await
                .context("querying nostr_seen_events")?;
        Ok(row.is_some())
    }

    /// Records that `event_id` has been dispatched, so a future duplicate delivery of it (a
    /// relay redelivering, or the next process restart's fresh subscription replaying history)
    /// is recognized and skipped.
    pub async fn mark_nostr_event_seen(&self, event_id: &str, seen_at: i64) -> Result<()> {
        sqlx::query(
            "INSERT INTO nostr_seen_events (event_id, seen_at) VALUES (?1, ?2)
             ON CONFLICT(event_id) DO NOTHING",
        )
        .bind(event_id)
        .bind(seen_at)
        .execute(&self.pool)
        .await
        .context("writing nostr_seen_events")?;
        Ok(())
    }

    /// Returns the current policy state, seeding it from `default_policy_json` (at version 1)
    /// if this is the first time the service has ever started against this database. On every
    /// later start, whatever is already in the database wins - `default_policy_json` (the
    /// TOML config's `[policy]` section) only ever matters once, for a brand-new deployment.
    pub async fn load_or_seed_policy_state(
        &self,
        default_policy_json: &str,
        now: i64,
    ) -> Result<PolicyState> {
        let mut ltx = self.begin().await?;
        if let Some(state) = ltx.get_policy_state().await? {
            ltx.rollback().await?;
            return Ok(state);
        }
        ltx.set_policy_state(1, default_policy_json, now).await?;
        ltx.commit().await?;
        Ok(PolicyState {
            version: 1,
            policy_json: default_policy_json.to_string(),
            updated_at: now,
        })
    }

    pub async fn get_policy_state(&self) -> Result<Option<PolicyState>> {
        let mut ltx = self.begin().await?;
        let state = ltx.get_policy_state().await?;
        ltx.rollback().await?;
        Ok(state)
    }

    /// txids of every `pending`-status row whose hold has elapsed as of `now` - what the
    /// background sweeper should attempt to process next. A plain pool read: each row gets
    /// re-checked for its current status inside its own transaction when actually processed,
    /// so a stale read here (e.g. a veto racing in after this query) is always caught later.
    /// Rows whose hold has elapsed **and** whose notification was confirmed delivered.
    ///
    /// The `notify_delivered` clause is a safety interlock, not an optimisation: a hold window
    /// nobody was told about provides no opportunity to veto, so signing on its expiry would be
    /// signing unsupervised. Undelivered rows stay `pending` indefinitely and are retried by
    /// [`Self::pending_needing_renotify`]; [`Self::due_pending_undelivered`] surfaces them so
    /// they can be alarmed on rather than silently stalling.
    pub async fn due_pending(&self, now: i64) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT txid FROM pending_signatures
             WHERE status = ?1 AND hold_until <= ?2 AND notify_delivered = 1",
        )
        .bind(PendingStatus::Pending.as_str())
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .context("querying due pending signatures")?;
        Ok(rows.into_iter().map(|(txid,)| txid).collect())
    }

    /// Rows that are past their hold but held back because no notification was ever confirmed
    /// delivered. Failing closed like this is correct but must not be silent - these are spends
    /// the operator asked for that are not progressing.
    pub async fn due_pending_undelivered(&self, now: i64) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT txid FROM pending_signatures
             WHERE status = ?1 AND hold_until <= ?2 AND notify_delivered = 0",
        )
        .bind(PendingStatus::Pending.as_str())
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .context("querying undelivered due pending signatures")?;
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

    /// Brings a still-`pending` row's hold forward to `now`, so the next sweep picks it up.
    /// Returns `false` if the row is missing or no longer pending.
    ///
    /// This is the *entire* effect a recovery-contact quorum is allowed to have - see
    /// `recovery_contacts.rs`. It touches only `hold_until`: the row keeps its status, its PSBT,
    /// its recorded amounts and its delivery flag, and `sign::process_due_pending_row`
    /// re-evaluates policy from scratch when it fires regardless of how it became due. A quorum
    /// therefore cannot raise a cap, reach a forbidden destination, or resurrect a vetoed spend -
    /// it can only stop this service waiting.
    pub async fn release_hold(&self, txid: &str, now: i64) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE pending_signatures SET hold_until = ?1 WHERE txid = ?2 AND status = ?3",
        )
        .bind(now)
        .bind(txid)
        .bind(PendingStatus::Pending.as_str())
        .execute(&self.pool)
        .await
        .context("releasing a pending hold")?;
        Ok(result.rows_affected() > 0)
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
            // `last_notified_at` starts at 0, not `created_at`: nothing has been delivered yet,
            // and seeding it to "now" made the re-notify sweeper treat a never-delivered row as
            // freshly notified and skip it for a full interval. `notify_delivered` starts at 0
            // so the row cannot be signed until a notification actually lands.
            "INSERT INTO pending_signatures
                (txid, psbt_base64, spend_amount_sat, fee_sat, created_at, hold_until, status,
                 last_notified_at, notify_delivered)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 0)",
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

    /// Same check as [`Ledger::is_frozen`], but read through this held transaction's own
    /// connection rather than a fresh pool acquire. The pool is `max_connections(1)`, so calling
    /// `Ledger::is_frozen` while a `LedgerTx` is open self-deadlocks: the transaction holds the
    /// only connection, and the fresh acquire blocks behind it until the pool's acquire timeout.
    pub async fn is_frozen(&mut self) -> Result<bool> {
        let row: Option<(i64,)> = sqlx::query_as("SELECT frozen FROM freeze_state WHERE id = 1")
            .fetch_optional(&mut *self.tx)
            .await
            .context("querying freeze_state")?;
        Ok(row.is_some_and(|(f,)| f != 0))
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

    pub async fn get_policy_state(&mut self) -> Result<Option<PolicyState>> {
        let row: Option<(i64, String, i64)> = sqlx::query_as(
            "SELECT version, policy_json, updated_at FROM policy_state WHERE id = 1",
        )
        .fetch_optional(&mut *self.tx)
        .await
        .context("querying policy_state")?;
        Ok(row.map(|(version, policy_json, updated_at)| PolicyState {
            version: version as u64,
            policy_json,
            updated_at,
        }))
    }

    pub async fn set_policy_state(
        &mut self,
        version: u64,
        policy_json: &str,
        updated_at: i64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO policy_state (id, version, policy_json, updated_at) VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET version = excluded.version, \
                policy_json = excluded.policy_json, updated_at = excluded.updated_at",
        )
        .bind(version as i64)
        .bind(policy_json)
        .bind(updated_at)
        .execute(&mut *self.tx)
        .await
        .context("writing policy_state")?;
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

        // A freshly inserted row is not yet due at any time: no notification has been confirmed
        // delivered for it. Marking delivery is what releases it.
        assert!(ledger.due_pending(801).await.unwrap().is_empty());
        ledger.mark_notified("tx-a", 500).await.unwrap();

        assert!(ledger.due_pending(799).await.unwrap().is_empty());
        assert_eq!(ledger.due_pending(800).await.unwrap(), vec!["tx-a"]);
        assert_eq!(ledger.due_pending(801).await.unwrap(), vec!["tx-a"]);
    }

    /// The interlock behind the notify-then-hold guarantee: a spend whose notification never
    /// landed must never be signed, no matter how long its hold has been over.
    ///
    /// `insert_pending` commits before the notification is sent, so a hung notifier or a restart
    /// in that window leaves a committed `pending` row nobody was told about. Without this,
    /// `due_pending` handed it to the sweeper on schedule and notify-then-hold silently became
    /// just-hold.
    #[tokio::test]
    async fn a_spend_nobody_was_notified_about_is_never_due_but_is_reported_as_stalled() {
        let ledger = Ledger::connect_in_memory().await.unwrap();
        let mut ltx = ledger.begin().await.unwrap();
        ltx.insert_pending("tx-silent", "cHNidA==", 1_000, 100, 500, 800)
            .await
            .unwrap();
        ltx.commit().await.unwrap();

        // Long past the hold, and still not signable.
        assert!(
            ledger.due_pending(999_999).await.unwrap().is_empty(),
            "an un-notified spend must never become due"
        );
        assert_eq!(
            ledger.due_pending_undelivered(999_999).await.unwrap(),
            vec!["tx-silent"],
            "...but it must be visible as stalled, not silently stuck"
        );

        // It also keeps being offered for re-notification past its hold, so delivery is retried
        // rather than abandoned.
        let retry = ledger
            .pending_needing_renotify(999_999, 3_600)
            .await
            .unwrap();
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].txid, "tx-silent");

        // Once a notification actually lands, it becomes due normally.
        ledger.mark_notified("tx-silent", 999_999).await.unwrap();
        assert_eq!(
            ledger.due_pending(999_999).await.unwrap(),
            vec!["tx-silent"]
        );
        assert!(ledger
            .due_pending_undelivered(999_999)
            .await
            .unwrap()
            .is_empty());
    }

    /// Rows written before `notify_delivered` existed were notified under the old code path, so
    /// the column defaults to 1 for them. Defaulting to 0 would strand every in-flight spend on
    /// upgrade as permanently unsignable.
    #[tokio::test]
    async fn rows_predating_the_delivery_flag_are_grandfathered_as_delivered() {
        let ledger = Ledger::connect_in_memory().await.unwrap();
        // Simulate a pre-migration row by inserting without the new column.
        sqlx::query(
            "INSERT INTO pending_signatures
                (txid, psbt_base64, spend_amount_sat, fee_sat, created_at, hold_until, status,
                 last_notified_at)
             VALUES ('tx-legacy', 'cHNidA==', 1000, 100, 500, 800, 'pending', 500)",
        )
        .execute(&ledger.pool)
        .await
        .unwrap();

        assert_eq!(ledger.due_pending(800).await.unwrap(), vec!["tx-legacy"]);
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

    #[tokio::test]
    async fn load_or_seed_policy_state_seeds_version_1_on_first_run() {
        let ledger = Ledger::connect_in_memory().await.unwrap();
        assert!(ledger.get_policy_state().await.unwrap().is_none());

        let state = ledger
            .load_or_seed_policy_state("{\"max_tx_sat\":1}", 1_000)
            .await
            .unwrap();
        assert_eq!(state.version, 1);
        assert_eq!(state.policy_json, "{\"max_tx_sat\":1}");
        assert_eq!(state.updated_at, 1_000);
        assert_eq!(ledger.get_policy_state().await.unwrap(), Some(state));
    }

    #[tokio::test]
    async fn load_or_seed_policy_state_does_not_reseed_an_existing_row() {
        let ledger = Ledger::connect_in_memory().await.unwrap();
        ledger
            .load_or_seed_policy_state("{\"max_tx_sat\":1}", 1_000)
            .await
            .unwrap();

        // A later call (as would happen on the next process restart) with a *different*
        // default must not clobber whatever's already there.
        let state = ledger
            .load_or_seed_policy_state("{\"max_tx_sat\":999}", 2_000)
            .await
            .unwrap();
        assert_eq!(state.version, 1);
        assert_eq!(state.policy_json, "{\"max_tx_sat\":1}");
    }

    #[tokio::test]
    async fn set_policy_state_upserts_and_advances_the_version() {
        let ledger = Ledger::connect_in_memory().await.unwrap();
        let mut ltx = ledger.begin().await.unwrap();
        ltx.set_policy_state(1, "{\"max_tx_sat\":1}", 1_000)
            .await
            .unwrap();
        ltx.set_policy_state(2, "{\"max_tx_sat\":2}", 2_000)
            .await
            .unwrap();
        ltx.commit().await.unwrap();

        let state = ledger.get_policy_state().await.unwrap().unwrap();
        assert_eq!(state.version, 2);
        assert_eq!(state.policy_json, "{\"max_tx_sat\":2}");
        assert_eq!(state.updated_at, 2_000);
    }

    #[tokio::test]
    async fn freeze_generation_starts_at_zero_and_survives_before_any_freeze() {
        let ledger = Ledger::connect_in_memory().await.unwrap();
        assert_eq!(ledger.freeze_generation().await.unwrap(), 0);
        assert!(!ledger.is_frozen().await.unwrap());
    }

    #[tokio::test]
    async fn freezing_increments_generation_but_unfreezing_never_does() {
        let ledger = Ledger::connect_in_memory().await.unwrap();

        ledger.set_frozen(true, 1_000, Some("first")).await.unwrap();
        assert!(ledger.is_frozen().await.unwrap());
        assert_eq!(ledger.freeze_generation().await.unwrap(), 1);

        ledger.set_frozen(false, 2_000, None).await.unwrap();
        assert!(!ledger.is_frozen().await.unwrap());
        assert_eq!(
            ledger.freeze_generation().await.unwrap(),
            1,
            "unfreezing must not advance the generation - only a NEW freeze does"
        );

        ledger
            .set_frozen(true, 3_000, Some("second"))
            .await
            .unwrap();
        assert_eq!(
            ledger.freeze_generation().await.unwrap(),
            2,
            "a second, later freeze must get a fresh generation - an authorization signed for \
             generation 1 must never be able to lift this one"
        );
    }

    #[tokio::test]
    async fn unfreezing_a_never_frozen_ledger_is_a_harmless_no_op() {
        let ledger = Ledger::connect_in_memory().await.unwrap();
        ledger.set_frozen(false, 1_000, None).await.unwrap();
        assert!(!ledger.is_frozen().await.unwrap());
        assert_eq!(ledger.freeze_generation().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn nostr_event_seen_tracking_is_idempotent_and_persists() {
        let ledger = Ledger::connect_in_memory().await.unwrap();
        assert!(!ledger.has_seen_nostr_event("abc123").await.unwrap());

        ledger.mark_nostr_event_seen("abc123", 1_000).await.unwrap();
        assert!(ledger.has_seen_nostr_event("abc123").await.unwrap());
        assert!(
            !ledger.has_seen_nostr_event("different-id").await.unwrap(),
            "a different event id must not be treated as seen"
        );

        // Marking the same id twice (e.g. two relays redelivering it) must not error.
        ledger.mark_nostr_event_seen("abc123", 2_000).await.unwrap();
        assert!(ledger.has_seen_nostr_event("abc123").await.unwrap());
    }
}
