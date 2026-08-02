//! The policy engine: decides whether an already-inspected PSBT (see `inspect.rs`) may be
//! signed. `evaluate_policy` is a pure function over (inspection report, ledger state,
//! config) - no I/O, no clock reads - specifically so it can be unit tested exhaustively,
//! including exact boundary values, without a database or a running server.
//!
//! Design choices worth being explicit about:
//! - The amount checked against every cap is the sum of `Destination`-kind outputs only -
//!   change and pay-to-self outputs come right back to the wallet, so counting them against
//!   a spend cap would make the cap meaningless for any transaction with change.
//! - Rolling day/week/month limits are checked against the *projected* cumulative total
//!   (prior spends from the ledger + this transaction), since that's the total that would
//!   exist immediately after this transaction is approved.
//! - A cap is exceeded by being strictly greater than the limit; a transaction that lands
//!   exactly on a limit is allowed ("above-threshold transactions are refused").
//! - There is no override path: `Deny` is a hard refusal, by design (per the M3 spec).

use std::fmt;
use std::str::FromStr;

use anyhow::{Context, Result};
use bitcoin::address::NetworkUnchecked;
use bitcoin::Address;
use serde::{Deserialize, Serialize};

use crate::config::ChainNetwork;
use crate::inspect::{InspectionReport, OutputKind};
use crate::ledger::RollingTotals;

/// Also `Serialize`, unlike most config-only structs in this crate: `policy_auth.rs` persists
/// this exact shape as JSON in `policy_state` and echoes it back from `GET /policy`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyConfig {
    pub max_tx_sat: u64,
    pub max_daily_sat: u64,
    pub max_weekly_sat: u64,
    pub max_monthly_sat: u64,
    pub max_fee_sat: u64,
    pub max_fee_rate_sat_per_vb: f64,
    /// If set, every destination output's address must appear in this list.
    #[serde(default)]
    pub destination_whitelist: Option<Vec<String>>,
}

impl PolicyConfig {
    /// Parses the whitelist (if any) into addresses checked against `network`, once, so
    /// `evaluate_policy` never has to parse or fail on a config error.
    pub fn compile(&self, network: ChainNetwork) -> Result<CompiledPolicy> {
        let destination_whitelist = self
            .destination_whitelist
            .as_ref()
            .map(|addrs| {
                addrs
                    .iter()
                    .map(|s| {
                        let addr = Address::<NetworkUnchecked>::from_str(s)
                            .with_context(|| format!("policy.destination_whitelist entry {s:?} is not a valid address"))?
                            .require_network(network.to_bitcoin_network())
                            .with_context(|| format!("policy.destination_whitelist entry {s:?} is not valid for {network:?}"))?;
                        Ok(addr)
                    })
                    .collect::<Result<Vec<Address>>>()
            })
            .transpose()?;

        Ok(CompiledPolicy {
            max_tx_sat: self.max_tx_sat,
            max_daily_sat: self.max_daily_sat,
            max_weekly_sat: self.max_weekly_sat,
            max_monthly_sat: self.max_monthly_sat,
            max_fee_sat: self.max_fee_sat,
            max_fee_rate_sat_per_vb: self.max_fee_rate_sat_per_vb,
            destination_whitelist,
        })
    }
}

/// A [`PolicyConfig`] with its whitelist pre-parsed and network-checked.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub max_tx_sat: u64,
    pub max_daily_sat: u64,
    pub max_weekly_sat: u64,
    pub max_monthly_sat: u64,
    pub max_fee_sat: u64,
    pub max_fee_rate_sat_per_vb: f64,
    pub destination_whitelist: Option<Vec<Address>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyViolation {
    ExceedsPerTransactionCap {
        spend_sat: u64,
        cap_sat: u64,
    },
    ExceedsDailyCap {
        projected_sat: u64,
        cap_sat: u64,
    },
    ExceedsWeeklyCap {
        projected_sat: u64,
        cap_sat: u64,
    },
    ExceedsMonthlyCap {
        projected_sat: u64,
        cap_sat: u64,
    },
    ExceedsMaxFee {
        fee_sat: u64,
        cap_sat: u64,
    },
    ExceedsMaxFeeRate {
        fee_rate_sat_per_vb: f64,
        cap_sat_per_vb: f64,
    },
    /// A destination output's address isn't on the whitelist.
    DestinationNotWhitelisted {
        output_index: usize,
        address: String,
    },
    /// A whitelist is configured but this destination output has no resolvable address at
    /// all (a non-standard script) - refused, since it can't be checked against the list.
    DestinationAddressUnresolvable {
        output_index: usize,
    },
}

impl fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyViolation::ExceedsPerTransactionCap { spend_sat, cap_sat } => {
                write!(
                    f,
                    "transaction sends {spend_sat} sat, over the {cap_sat} sat per-transaction cap"
                )
            }
            PolicyViolation::ExceedsDailyCap {
                projected_sat,
                cap_sat,
            } => {
                write!(f, "would bring the trailing 24h total to {projected_sat} sat, over the {cap_sat} sat daily cap")
            }
            PolicyViolation::ExceedsWeeklyCap {
                projected_sat,
                cap_sat,
            } => {
                write!(f, "would bring the trailing 7d total to {projected_sat} sat, over the {cap_sat} sat weekly cap")
            }
            PolicyViolation::ExceedsMonthlyCap {
                projected_sat,
                cap_sat,
            } => {
                write!(f, "would bring the trailing 30d total to {projected_sat} sat, over the {cap_sat} sat monthly cap")
            }
            PolicyViolation::ExceedsMaxFee { fee_sat, cap_sat } => {
                write!(f, "fee is {fee_sat} sat, over the {cap_sat} sat max fee")
            }
            PolicyViolation::ExceedsMaxFeeRate {
                fee_rate_sat_per_vb,
                cap_sat_per_vb,
            } => {
                write!(f, "fee rate is {fee_rate_sat_per_vb:.2} sat/vB, over the {cap_sat_per_vb:.2} sat/vB max")
            }
            PolicyViolation::DestinationNotWhitelisted {
                output_index,
                address,
            } => {
                write!(f, "output {output_index} pays {address}, which is not on the destination whitelist")
            }
            PolicyViolation::DestinationAddressUnresolvable { output_index } => {
                write!(f, "output {output_index} has no resolvable address, so it can't be checked against the destination whitelist")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyDecision {
    Allow,
    /// Refused outright. There is no override path in this milestone.
    Deny(Vec<PolicyViolation>),
}

impl PolicyDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, PolicyDecision::Allow)
    }
}

/// The amount actually leaving the wallet: destination outputs only. Change and
/// pay-to-self outputs are excluded - see the module doc for why. `pub(crate)` because
/// `sign.rs` needs the exact same number to record against the ledger.
pub(crate) fn destination_total_sat(report: &InspectionReport) -> u64 {
    report
        .outputs
        .iter()
        .filter(|o| o.kind == OutputKind::Destination)
        .map(|o| o.amount.to_sat())
        .sum()
}

pub fn evaluate_policy(
    report: &InspectionReport,
    rolling: &RollingTotals,
    policy: &CompiledPolicy,
) -> PolicyDecision {
    let mut violations = Vec::new();
    let spend_sat = destination_total_sat(report);

    if spend_sat > policy.max_tx_sat {
        violations.push(PolicyViolation::ExceedsPerTransactionCap {
            spend_sat,
            cap_sat: policy.max_tx_sat,
        });
    }

    let projected_day = rolling.day_sat + spend_sat;
    if projected_day > policy.max_daily_sat {
        violations.push(PolicyViolation::ExceedsDailyCap {
            projected_sat: projected_day,
            cap_sat: policy.max_daily_sat,
        });
    }
    let projected_week = rolling.week_sat + spend_sat;
    if projected_week > policy.max_weekly_sat {
        violations.push(PolicyViolation::ExceedsWeeklyCap {
            projected_sat: projected_week,
            cap_sat: policy.max_weekly_sat,
        });
    }
    let projected_month = rolling.month_sat + spend_sat;
    if projected_month > policy.max_monthly_sat {
        violations.push(PolicyViolation::ExceedsMonthlyCap {
            projected_sat: projected_month,
            cap_sat: policy.max_monthly_sat,
        });
    }

    let fee_sat = report.fee.to_sat();
    if fee_sat > policy.max_fee_sat {
        violations.push(PolicyViolation::ExceedsMaxFee {
            fee_sat,
            cap_sat: policy.max_fee_sat,
        });
    }
    if report.fee_rate_sat_per_vb > policy.max_fee_rate_sat_per_vb {
        violations.push(PolicyViolation::ExceedsMaxFeeRate {
            fee_rate_sat_per_vb: report.fee_rate_sat_per_vb,
            cap_sat_per_vb: policy.max_fee_rate_sat_per_vb,
        });
    }

    if let Some(whitelist) = &policy.destination_whitelist {
        for (i, output) in report.outputs.iter().enumerate() {
            if output.kind != OutputKind::Destination {
                continue;
            }
            match &output.address {
                Some(addr) if whitelist.contains(addr) => {}
                Some(addr) => violations.push(PolicyViolation::DestinationNotWhitelisted {
                    output_index: i,
                    address: addr.to_string(),
                }),
                None => violations
                    .push(PolicyViolation::DestinationAddressUnresolvable { output_index: i }),
            }
        }
    }

    if violations.is_empty() {
        PolicyDecision::Allow
    } else {
        PolicyDecision::Deny(violations)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{Amount, Network, ScriptBuf};

    use super::*;
    use crate::inspect::{InspectionReport, OutputReport, SpendingPath};

    fn script(fill: u8) -> ScriptBuf {
        let mut bytes = vec![0x00, 0x20];
        bytes.extend_from_slice(&[fill; 32]);
        ScriptBuf::from(bytes)
    }

    fn address(fill: u8) -> Address {
        Address::from_script(&script(fill), Network::Regtest).unwrap()
    }

    fn destination(amount_sat: u64, fill: u8) -> OutputReport {
        OutputReport {
            script_pubkey: script(fill),
            address: Some(address(fill)),
            amount: Amount::from_sat(amount_sat),
            kind: OutputKind::Destination,
        }
    }

    fn destination_unresolvable(amount_sat: u64) -> OutputReport {
        OutputReport {
            script_pubkey: ScriptBuf::new(),
            address: None,
            amount: Amount::from_sat(amount_sat),
            kind: OutputKind::Destination,
        }
    }

    fn change(amount_sat: u64) -> OutputReport {
        OutputReport {
            script_pubkey: script(0xEE),
            address: Some(address(0xEE)),
            amount: Amount::from_sat(amount_sat),
            kind: OutputKind::Change,
        }
    }

    fn report(
        outputs: Vec<OutputReport>,
        fee_sat: u64,
        fee_rate_sat_per_vb: f64,
    ) -> InspectionReport {
        let total_out: Amount = outputs.iter().map(|o| o.amount).sum();
        InspectionReport {
            inputs: vec![],
            outputs,
            total_in: total_out + Amount::from_sat(fee_sat),
            total_out,
            fee: Amount::from_sat(fee_sat),
            estimated_vsize: 200,
            fee_rate_sat_per_vb,
            spending_path: SpendingPath::Hot,
        }
    }

    fn generous_policy() -> CompiledPolicy {
        CompiledPolicy {
            max_tx_sat: u64::MAX,
            max_daily_sat: u64::MAX,
            max_weekly_sat: u64::MAX,
            max_monthly_sat: u64::MAX,
            max_fee_sat: u64::MAX,
            max_fee_rate_sat_per_vb: f64::MAX,
            destination_whitelist: None,
        }
    }

    fn no_prior_spends() -> RollingTotals {
        RollingTotals::default()
    }

    // ---- per-transaction cap ----

    #[test]
    fn per_tx_cap_boundary_is_exact() {
        let mut policy = generous_policy();
        policy.max_tx_sat = 100_000;

        let allowed = report(vec![destination(100_000, 1)], 0, 0.0);
        assert_eq!(
            evaluate_policy(&allowed, &no_prior_spends(), &policy),
            PolicyDecision::Allow
        );

        let denied = report(vec![destination(100_001, 1)], 0, 0.0);
        let PolicyDecision::Deny(violations) =
            evaluate_policy(&denied, &no_prior_spends(), &policy)
        else {
            panic!("expected denial");
        };
        assert_eq!(
            violations,
            vec![PolicyViolation::ExceedsPerTransactionCap {
                spend_sat: 100_001,
                cap_sat: 100_000
            }]
        );
    }

    #[test]
    fn per_tx_cap_ignores_change_and_own_receive() {
        let mut policy = generous_policy();
        policy.max_tx_sat = 1_000;

        // 1_000_000 sat of change alongside a 1_000 sat destination must not trip the cap.
        let r = report(vec![destination(1_000, 1), change(1_000_000)], 0, 0.0);
        assert_eq!(
            evaluate_policy(&r, &no_prior_spends(), &policy),
            PolicyDecision::Allow
        );
    }

    // ---- rolling limits ----

    #[test]
    fn daily_cap_boundary_accounts_for_prior_spends() {
        let mut policy = generous_policy();
        policy.max_daily_sat = 10_000;
        let rolling = RollingTotals {
            day_sat: 9_000,
            week_sat: 9_000,
            month_sat: 9_000,
        };

        let allowed = report(vec![destination(1_000, 1)], 0, 0.0); // 9_000 + 1_000 == 10_000
        assert_eq!(
            evaluate_policy(&allowed, &rolling, &policy),
            PolicyDecision::Allow
        );

        let denied = report(vec![destination(1_001, 1)], 0, 0.0); // 9_000 + 1_001 > 10_000
        let PolicyDecision::Deny(violations) = evaluate_policy(&denied, &rolling, &policy) else {
            panic!("expected denial");
        };
        assert_eq!(
            violations,
            vec![PolicyViolation::ExceedsDailyCap {
                projected_sat: 10_001,
                cap_sat: 10_000
            }]
        );
    }

    #[test]
    fn weekly_cap_boundary_accounts_for_prior_spends() {
        let mut policy = generous_policy();
        policy.max_weekly_sat = 50_000;
        let rolling = RollingTotals {
            day_sat: 0,
            week_sat: 49_000,
            month_sat: 49_000,
        };

        let allowed = report(vec![destination(1_000, 1)], 0, 0.0);
        assert_eq!(
            evaluate_policy(&allowed, &rolling, &policy),
            PolicyDecision::Allow
        );

        let denied = report(vec![destination(1_001, 1)], 0, 0.0);
        assert!(!evaluate_policy(&denied, &rolling, &policy).is_allowed());
    }

    #[test]
    fn monthly_cap_boundary_accounts_for_prior_spends() {
        let mut policy = generous_policy();
        policy.max_monthly_sat = 200_000;
        let rolling = RollingTotals {
            day_sat: 0,
            week_sat: 0,
            month_sat: 199_000,
        };

        let allowed = report(vec![destination(1_000, 1)], 0, 0.0);
        assert_eq!(
            evaluate_policy(&allowed, &rolling, &policy),
            PolicyDecision::Allow
        );

        let denied = report(vec![destination(1_001, 1)], 0, 0.0);
        assert!(!evaluate_policy(&denied, &rolling, &policy).is_allowed());
    }

    #[test]
    fn a_transaction_within_its_own_cap_can_still_be_denied_by_a_rolling_cap() {
        let mut policy = generous_policy();
        policy.max_tx_sat = 1_000_000; // this transaction alone is fine
        policy.max_daily_sat = 500; // but the day is nearly spent already
        let rolling = RollingTotals {
            day_sat: 400,
            week_sat: 400,
            month_sat: 400,
        };

        let r = report(vec![destination(200, 1)], 0, 0.0); // 400 + 200 = 600 > 500
        let PolicyDecision::Deny(violations) = evaluate_policy(&r, &rolling, &policy) else {
            panic!("expected denial");
        };
        assert_eq!(
            violations,
            vec![PolicyViolation::ExceedsDailyCap {
                projected_sat: 600,
                cap_sat: 500
            }]
        );
    }

    // ---- fee limits ----

    #[test]
    fn max_fee_boundary_is_exact() {
        let mut policy = generous_policy();
        policy.max_fee_sat = 5_000;

        let allowed = report(vec![destination(1_000, 1)], 5_000, 1.0);
        assert_eq!(
            evaluate_policy(&allowed, &no_prior_spends(), &policy),
            PolicyDecision::Allow
        );

        let denied = report(vec![destination(1_000, 1)], 5_001, 1.0);
        let PolicyDecision::Deny(violations) =
            evaluate_policy(&denied, &no_prior_spends(), &policy)
        else {
            panic!("expected denial");
        };
        assert_eq!(
            violations,
            vec![PolicyViolation::ExceedsMaxFee {
                fee_sat: 5_001,
                cap_sat: 5_000
            }]
        );
    }

    #[test]
    fn max_fee_rate_boundary_is_exact() {
        let mut policy = generous_policy();
        policy.max_fee_rate_sat_per_vb = 50.0;

        let allowed = report(vec![destination(1_000, 1)], 1_000, 50.0);
        assert_eq!(
            evaluate_policy(&allowed, &no_prior_spends(), &policy),
            PolicyDecision::Allow
        );

        let denied = report(vec![destination(1_000, 1)], 1_000, 50.0001);
        let PolicyDecision::Deny(violations) =
            evaluate_policy(&denied, &no_prior_spends(), &policy)
        else {
            panic!("expected denial");
        };
        assert_eq!(
            violations,
            vec![PolicyViolation::ExceedsMaxFeeRate {
                fee_rate_sat_per_vb: 50.0001,
                cap_sat_per_vb: 50.0
            }]
        );
    }

    // ---- destination whitelist ----

    #[test]
    fn whitelist_allows_listed_addresses_and_denies_others() {
        let mut policy = generous_policy();
        policy.destination_whitelist = Some(vec![address(1)]);

        let allowed = report(vec![destination(1_000, 1)], 0, 0.0);
        assert_eq!(
            evaluate_policy(&allowed, &no_prior_spends(), &policy),
            PolicyDecision::Allow
        );

        let denied = report(vec![destination(1_000, 2)], 0, 0.0);
        let PolicyDecision::Deny(violations) =
            evaluate_policy(&denied, &no_prior_spends(), &policy)
        else {
            panic!("expected denial");
        };
        assert_eq!(
            violations,
            vec![PolicyViolation::DestinationNotWhitelisted {
                output_index: 0,
                address: address(2).to_string()
            }]
        );
    }

    #[test]
    fn whitelist_does_not_apply_to_change_or_own_receive_outputs() {
        let mut policy = generous_policy();
        policy.destination_whitelist = Some(vec![address(1)]);

        // The change output's address (0xEE) is deliberately not on the whitelist - it must
        // not be checked, since the whitelist only governs money actually leaving the wallet.
        let r = report(vec![destination(1_000, 1), change(500)], 0, 0.0);
        assert_eq!(
            evaluate_policy(&r, &no_prior_spends(), &policy),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn whitelist_denies_a_destination_with_no_resolvable_address() {
        let mut policy = generous_policy();
        policy.destination_whitelist = Some(vec![address(1)]);

        let r = report(vec![destination_unresolvable(1_000)], 0, 0.0);
        let PolicyDecision::Deny(violations) = evaluate_policy(&r, &no_prior_spends(), &policy)
        else {
            panic!("expected denial");
        };
        assert_eq!(
            violations,
            vec![PolicyViolation::DestinationAddressUnresolvable { output_index: 0 }]
        );
    }

    #[test]
    fn no_whitelist_configured_allows_any_destination() {
        let policy = generous_policy(); // destination_whitelist: None
        let r = report(vec![destination(1_000, 42)], 0, 0.0);
        assert_eq!(
            evaluate_policy(&r, &no_prior_spends(), &policy),
            PolicyDecision::Allow
        );
    }

    // ---- multiple simultaneous violations ----

    #[test]
    fn reports_every_violation_at_once_not_just_the_first() {
        let mut policy = generous_policy();
        policy.max_tx_sat = 100;
        policy.max_fee_sat = 10;
        policy.destination_whitelist = Some(vec![address(1)]);

        let r = report(vec![destination(1_000, 2)], 20, 0.0);
        let PolicyDecision::Deny(violations) = evaluate_policy(&r, &no_prior_spends(), &policy)
        else {
            panic!("expected denial");
        };
        assert_eq!(
            violations.len(),
            3,
            "expected per-tx cap, fee cap, and whitelist violations together: {violations:?}"
        );
    }

    // ---- compiling a config into a policy ----

    #[test]
    fn compile_parses_whitelist_addresses_for_the_configured_network() {
        let cfg = PolicyConfig {
            max_tx_sat: 1,
            max_daily_sat: 1,
            max_weekly_sat: 1,
            max_monthly_sat: 1,
            max_fee_sat: 1,
            max_fee_rate_sat_per_vb: 1.0,
            destination_whitelist: Some(vec![address(1).to_string()]),
        };
        let compiled = cfg.compile(ChainNetwork::Regtest).unwrap();
        assert_eq!(compiled.destination_whitelist, Some(vec![address(1)]));
    }

    #[test]
    fn compile_rejects_a_malformed_whitelist_address() {
        let cfg = PolicyConfig {
            max_tx_sat: 1,
            max_daily_sat: 1,
            max_weekly_sat: 1,
            max_monthly_sat: 1,
            max_fee_sat: 1,
            max_fee_rate_sat_per_vb: 1.0,
            destination_whitelist: Some(vec!["not-an-address".to_string()]),
        };
        assert!(cfg.compile(ChainNetwork::Regtest).is_err());
    }

    #[test]
    fn compile_rejects_an_address_for_the_wrong_network() {
        let mainnet_address = Address::from_script(&script(1), Network::Bitcoin).unwrap();
        let cfg = PolicyConfig {
            max_tx_sat: 1,
            max_daily_sat: 1,
            max_weekly_sat: 1,
            max_monthly_sat: 1,
            max_fee_sat: 1,
            max_fee_rate_sat_per_vb: 1.0,
            destination_whitelist: Some(vec![mainnet_address.to_string()]),
        };
        assert!(cfg.compile(ChainNetwork::Regtest).is_err());
    }
}
