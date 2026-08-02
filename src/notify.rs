//! Out-of-band notification for the M5 notify-then-hold-then-sign flow: before this service
//! ever signs an approved HOT-path spend, a human is told about it - over ntfy and/or email -
//! with enough detail to decide whether to veto it (`POST /veto/{id}`) before the hold elapses.
//!
//! Delivery failure is treated as fatal to the submission that triggered it: a hold nobody was
//! told about would defeat the entire point of this milestone, so `submit_for_signing` (in
//! `sign.rs`) never lets a spend sit in the queue without at least attempting - and confirming
//! success of - every configured channel.

use anyhow::{Context, Result};
use async_trait::async_trait;

use crate::config::{NotifyConfig, NtfyConfig, SmtpConfig};

/// Everything a human needs to decide whether to veto a pending spend.
#[derive(Debug, Clone)]
pub struct PendingNotice<'a> {
    pub txid: &'a str,
    pub spend_sat: u64,
    pub fee_sat: u64,
    pub destinations: &'a [String],
    pub hold_until: i64,
}

fn format_message(notice: &PendingNotice) -> String {
    let destinations = if notice.destinations.is_empty() {
        "(none)".to_string()
    } else {
        notice.destinations.join(", ")
    };
    format!(
        "cosigner: pending HOT-path spend {txid}\n\
         amount: {spend_sat} sat (fee {fee_sat} sat)\n\
         destinations: {destinations}\n\
         will sign at unix time {hold_until} unless vetoed first\n\
         to cancel: POST /veto/{txid}",
        txid = notice.txid,
        spend_sat = notice.spend_sat,
        fee_sat = notice.fee_sat,
        destinations = destinations,
        hold_until = notice.hold_until,
    )
}

#[async_trait]
pub trait Notifier: Send + Sync {
    async fn notify(&self, notice: &PendingNotice<'_>) -> Result<()>;
}

pub struct NtfyNotifier {
    client: reqwest::Client,
    cfg: NtfyConfig,
}

impl NtfyNotifier {
    pub fn new(cfg: NtfyConfig) -> Self {
        Self {
            client: reqwest::Client::new(),
            cfg,
        }
    }
}

#[async_trait]
impl Notifier for NtfyNotifier {
    async fn notify(&self, notice: &PendingNotice<'_>) -> Result<()> {
        let mut req = self
            .client
            .post(&self.cfg.url)
            .header("Title", format!("cosigner: pending spend {}", notice.txid))
            .body(format_message(notice));
        if let Some(token) = &self.cfg.auth_token {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await.context("sending ntfy notification")?;
        if !resp.status().is_success() {
            anyhow::bail!("ntfy notification failed: HTTP {}", resp.status());
        }
        Ok(())
    }
}

pub struct SmtpNotifier {
    transport: lettre::AsyncSmtpTransport<lettre::Tokio1Executor>,
    from: lettre::message::Mailbox,
    to: lettre::message::Mailbox,
}

impl SmtpNotifier {
    pub fn new(cfg: &SmtpConfig) -> Result<Self> {
        use lettre::transport::smtp::authentication::Credentials;
        use lettre::{AsyncSmtpTransport, Tokio1Executor};

        let transport = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)
            .with_context(|| format!("configuring SMTP relay to {}", cfg.host))?
            .port(cfg.port)
            .credentials(Credentials::new(cfg.username.clone(), cfg.password.clone()))
            .build();
        let from = cfg
            .from
            .parse()
            .with_context(|| format!("notify.smtp.from {:?} is not a valid mailbox", cfg.from))?;
        let to = cfg
            .to
            .parse()
            .with_context(|| format!("notify.smtp.to {:?} is not a valid mailbox", cfg.to))?;
        Ok(Self {
            transport,
            from,
            to,
        })
    }
}

#[async_trait]
impl Notifier for SmtpNotifier {
    async fn notify(&self, notice: &PendingNotice<'_>) -> Result<()> {
        use lettre::AsyncTransport;

        let email = lettre::Message::builder()
            .from(self.from.clone())
            .to(self.to.clone())
            .subject(format!("cosigner: pending spend {}", notice.txid))
            .body(format_message(notice))
            .context("building notification email")?;
        self.transport
            .send(email)
            .await
            .context("sending SMTP notification")?;
        Ok(())
    }
}

/// Fans a notice out to every configured channel. All of them must succeed - see the module
/// doc for why a partial failure here can't be treated as "good enough".
pub struct MultiNotifier {
    channels: Vec<Box<dyn Notifier>>,
}

impl MultiNotifier {
    pub fn from_config(cfg: &NotifyConfig) -> Result<Self> {
        let mut channels: Vec<Box<dyn Notifier>> = Vec::new();
        if let Some(ntfy) = &cfg.ntfy {
            channels.push(Box::new(NtfyNotifier::new(ntfy.clone())));
        }
        if let Some(smtp) = &cfg.smtp {
            channels.push(Box::new(SmtpNotifier::new(smtp)?));
        }
        Ok(Self { channels })
    }
}

#[async_trait]
impl Notifier for MultiNotifier {
    async fn notify(&self, notice: &PendingNotice<'_>) -> Result<()> {
        for channel in &self.channels {
            channel.notify(notice).await?;
        }
        Ok(())
    }
}

/// A notifier that does nothing and always succeeds. Never reachable from `[notify]` config -
/// [`MultiNotifier::from_config`] only ever builds real (ntfy/SMTP) channels - so this exists
/// purely for tests and fixtures that need a complete `AppState` but don't exercise
/// `/sign_psbt`'s notify-then-hold flow.
pub struct NoopNotifier;

#[async_trait]
impl Notifier for NoopNotifier {
    async fn notify(&self, _notice: &PendingNotice<'_>) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod mock {
    use std::sync::Mutex;

    use super::*;

    /// Records every notification it receives (as owned strings, since `PendingNotice`
    /// borrows) instead of delivering anywhere - lets tests assert a notification was sent,
    /// and inspect its content, without any real network I/O.
    #[derive(Default)]
    pub struct RecordingNotifier {
        pub sent: Mutex<Vec<String>>,
        pub fail: bool,
    }

    impl RecordingNotifier {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn failing() -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
                fail: true,
            }
        }
    }

    #[async_trait]
    impl Notifier for RecordingNotifier {
        async fn notify(&self, notice: &PendingNotice<'_>) -> Result<()> {
            if self.fail {
                anyhow::bail!("mock notifier configured to fail");
            }
            self.sent.lock().unwrap().push(notice.txid.to_string());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_a_human_readable_message() {
        let notice = PendingNotice {
            txid: "abc123",
            spend_sat: 50_000,
            fee_sat: 500,
            destinations: &["bc1qexample".to_string()],
            hold_until: 1_700_000_000,
        };
        let msg = format_message(&notice);
        assert!(msg.contains("abc123"));
        assert!(msg.contains("50000"));
        assert!(msg.contains("bc1qexample"));
        assert!(msg.contains("/veto/abc123"));
    }

    #[tokio::test]
    async fn multi_notifier_with_no_channels_configured_succeeds_trivially() {
        let multi = MultiNotifier { channels: vec![] };
        let notice = PendingNotice {
            txid: "abc",
            spend_sat: 1,
            fee_sat: 1,
            destinations: &[],
            hold_until: 0,
        };
        multi.notify(&notice).await.unwrap();
    }
}
