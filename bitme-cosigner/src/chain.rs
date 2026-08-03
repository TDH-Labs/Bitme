//! Access to authoritative on-chain state. PSBTs are untrusted input - a PSBT's own claims
//! about what a prevout looks like (`witness_utxo`) must never be taken at face value, so
//! every input is re-checked against this source before we compute amounts, fees, or policy
//! decisions from it.

use anyhow::{Context, Result};
use bitcoin::{OutPoint, ScriptBuf, TxOut};

/// The current state of a single outpoint, as known to the node right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utxo {
    pub txout: TxOut,
    pub confirmations: u32,
}

pub trait ChainSource: Send + Sync {
    /// The authoritative current state of `outpoint`: `Ok(None)` if it doesn't exist or has
    /// already been spent (including by the mempool), `Ok(Some(_))` if it's presently
    /// spendable. Includes mempool-only UTXOs (with `confirmations == 0`) so callers can see
    /// and reason about them explicitly, rather than have them silently look nonexistent.
    fn get_utxo(&self, outpoint: OutPoint) -> Result<Option<Utxo>>;
}

pub struct BitcoindRpc {
    client: bitcoincore_rpc::Client,
}

impl BitcoindRpc {
    pub fn new(client: bitcoincore_rpc::Client) -> Self {
        Self { client }
    }
}

impl ChainSource for BitcoindRpc {
    fn get_utxo(&self, outpoint: OutPoint) -> Result<Option<Utxo>> {
        use bitcoincore_rpc::RpcApi;

        let result = self
            .client
            .get_tx_out(&outpoint.txid, outpoint.vout, Some(true))
            .with_context(|| format!("gettxout {}:{}", outpoint.txid, outpoint.vout))?;

        Ok(result.map(|r| Utxo {
            txout: TxOut {
                value: r.value,
                script_pubkey: ScriptBuf::from(r.script_pub_key.hex),
            },
            confirmations: r.confirmations,
        }))
    }
}

#[cfg(test)]
pub(crate) mod mock {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    /// An in-memory chain source for unit tests: a fixed set of outpoints exist with given
    /// state; everything else looks unspent/nonexistent, exactly like a real node's gettxout.
    #[derive(Default)]
    pub struct MockChainSource {
        utxos: Mutex<HashMap<OutPoint, Utxo>>,
    }

    impl MockChainSource {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn insert(&self, outpoint: OutPoint, utxo: Utxo) {
            self.utxos.lock().unwrap().insert(outpoint, utxo);
        }
    }

    impl ChainSource for MockChainSource {
        fn get_utxo(&self, outpoint: OutPoint) -> Result<Option<Utxo>> {
            Ok(self.utxos.lock().unwrap().get(&outpoint).cloned())
        }
    }
}
