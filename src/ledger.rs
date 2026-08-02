//! The spend ledger: a durable SQLite record of every signature this service has produced,
//! used to enforce the rolling day/week/month spend limits in `policy.rs`.
//!
//! This module owns all SQL. The policy engine never touches the database directly - it
//! consumes a plain [`RollingTotals`] snapshot, so it stays a pure function that can be
//! tested exhaustively without a database. `record_spend` here is deliberately bare (no
//! idempotency key, no transactional coupling to the sign operation that produced it): M4
//! adds both when it wires this into `/sign_psbt`.

use anyhow::{Context, Result};
use sqlx::sqlite::SqlitePool;

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
    pub async fn connect(path: &str) -> Result<Self> {
        let pool = SqlitePool::connect(&format!("sqlite://{path}?mode=rwc"))
            .await
            .with_context(|| format!("opening ledger database at {path}"))?;
        let ledger = Self { pool };
        ledger.migrate().await?;
        Ok(ledger)
    }

    /// An ephemeral in-memory database - for tests only.
    pub async fn connect_in_memory() -> Result<Self> {
        let pool = SqlitePool::connect("sqlite::memory:")
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

    /// Appends one spend to the ledger, timestamped `recorded_at` (unix seconds).
    pub async fn record_spend(
        &self,
        recorded_at: i64,
        spend_amount_sat: u64,
        fee_sat: u64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO ledger (recorded_at, spend_amount_sat, fee_sat) VALUES (?1, ?2, ?3)",
        )
        .bind(recorded_at)
        .bind(spend_amount_sat as i64)
        .bind(fee_sat as i64)
        .execute(&self.pool)
        .await
        .context("recording spend in ledger")?;
        Ok(())
    }

    /// Sums `spend_amount_sat` over the trailing day/week/month windows ending at `now`
    /// (unix seconds). An entry counts toward a window while its age is strictly less than
    /// the window length - i.e. windows are the half-open interval `(now - length, now]`.
    pub async fn rolling_totals(&self, now: i64) -> Result<RollingTotals> {
        let rows: Vec<(i64, i64)> = sqlx::query_as(
            "SELECT recorded_at, spend_amount_sat FROM ledger WHERE recorded_at > ?1",
        )
        .bind(now - MONTH_SECONDS)
        .fetch_all(&self.pool)
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

        ledger.record_spend(now, 1_000, 10).await.unwrap(); // right now: in all windows
        ledger
            .record_spend(now - DAY_SECONDS + 1, 2_000, 10)
            .await
            .unwrap(); // just inside the day window
        ledger
            .record_spend(now - WEEK_SECONDS + 1, 4_000, 10)
            .await
            .unwrap(); // inside week, not day
        ledger
            .record_spend(now - MONTH_SECONDS + 1, 8_000, 10)
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
            ledger.record_spend(now - age, 1_000, 0).await.unwrap();
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
        ledger.record_spend(now + 100, 5_000, 0).await.unwrap();
        let totals = ledger.rolling_totals(now).await.unwrap();
        assert_eq!(totals, RollingTotals::default());
    }
}
