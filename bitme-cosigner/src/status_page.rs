//! The `GET /` page for a *configured* service.
//!
//! Before this existed, `/` had no route at all: once setup was done and the wizard was gone,
//! opening the app from Umbrel's dashboard returned a bare `HTTP 404 - No webpage was found`.
//! Every doc in this repo claimed opening it showed "a small JSON health check", which was only
//! ever true of `/health` - `/` returned nothing at all.
//!
//! It also solves a real operational problem. The wallet descriptor is only shown once, on the
//! last screen of the setup wizard, and that screen is gone forever after the first restart.
//! Anyone who didn't capture it then - or whose coordinator rejected the one format the wizard
//! offered - had no way to get it back short of the `descriptor build` CLI over SSH. This page
//! serves all three encodings, with QRs, on demand.
//!
//! Nothing here is sensitive: descriptors and addresses are public, and the page shows no key
//! material. It sits behind Umbrel's `app_proxy` session auth regardless.

use crate::config::WalletConfig;
use crate::descriptor::{self, BuiltDescriptor};
use crate::setup::qr_svg;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// One selectable descriptor encoding, with its QR.
struct Encoding {
    id: &'static str,
    label: &'static str,
    text: String,
    qr: Option<String>,
}

pub fn render(wallet: &BuiltDescriptor, cfg: &WalletConfig, policy_version: u64) -> String {
    let network = crate::wizard::network_str(cfg.network);
    let encodings = [
        ("combined", "Combined", wallet.multipath.to_string()),
        ("receive", "Receive only", wallet.external.to_string()),
        ("change", "Change only", wallet.internal.to_string()),
    ]
    .into_iter()
    .map(|(id, label, text)| Encoding {
        id,
        label,
        qr: qr_svg(&text),
        text,
    })
    .collect::<Vec<_>>();

    let first_address = descriptor::address_at(&wallet.external, 0, cfg.network)
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unavailable".to_string());

    let tabs = encodings
        .iter()
        .enumerate()
        .map(|(i, e)| {
            format!(
                r#"<button class="tab{}" data-t="{}">{}</button>"#,
                if i == 0 { " on" } else { "" },
                e.id,
                e.label
            )
        })
        .collect::<String>();

    let panes = encodings
        .iter()
        .enumerate()
        .map(|(i, e)| {
            format!(
                r#"<div class="pane{}" id="p-{}">{}<pre>{}</pre></div>"#,
                if i == 0 { "" } else { " hidden" },
                e.id,
                e.qr.as_deref()
                    .map(|q| format!(r#"<div class="qr">{q}</div>"#))
                    .unwrap_or_default(),
                esc(&e.text)
            )
        })
        .collect::<String>();

    let mainnet_badge = if cfg.network == crate::config::ChainNetwork::Mainnet {
        " mainnet"
    } else {
        ""
    };

    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bitme Cosigner</title>
<style>
:root {{ --bg:#f6f7f9; --panel:#fff; --ink:#14171a; --muted:#5c6570; --line:#dfe3e8;
        --accent:#f7931a; --accent-ink:#1a1005; --ok:#1a7f45; --code-bg:#f0f2f5; }}
@media (prefers-color-scheme:dark) {{ :root {{ --bg:#111417; --panel:#1a1e22; --ink:#e8eaed;
        --muted:#98a2ad; --line:#2c3238; --ok:#56d38a; --code-bg:#101316; }} }}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);
     font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}}
.wrap{{max-width:760px;margin:0 auto;padding:32px 20px 80px}}
header{{display:flex;align-items:baseline;gap:12px}}
h1{{font-size:21px;margin:0}}
.net{{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;padding:3px 8px;
     border-radius:999px;border:1px solid var(--line);color:var(--muted)}}
.net.mainnet{{color:var(--accent-ink);background:var(--accent);border-color:var(--accent)}}
.sub{{color:var(--muted);margin:6px 0 24px;font-size:14px}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:24px;margin-bottom:16px}}
.card h2{{font-size:17px;margin:0 0 6px}} .card p{{color:var(--muted);margin:0 0 16px}}
.kv{{display:flex;justify-content:space-between;gap:16px;padding:7px 0;border-bottom:1px solid var(--line);font-size:14px}}
.kv:last-child{{border-bottom:0}} .kv span:first-child{{color:var(--muted)}}
.kv span:last-child{{text-align:right;font-family:ui-monospace,Menlo,monospace;font-size:12.5px;word-break:break-all}}
.tabs{{display:flex;gap:6px;margin-bottom:14px}}
.tab{{flex:1;font:inherit;font-weight:600;padding:8px 12px;border-radius:8px;cursor:pointer;
     background:transparent;color:var(--muted);border:1px solid var(--line)}}
.tab.on{{background:var(--accent);color:var(--accent-ink);border-color:var(--accent)}}
pre{{font-family:ui-monospace,Menlo,Consolas,monospace;background:var(--code-bg);border:1px solid var(--line);
    border-radius:6px;padding:12px;font-size:12.5px;white-space:pre-wrap;word-break:break-all;margin:0}}
.qr{{text-align:center;margin:16px 0}}
.qr svg{{width:min(340px,86vw);height:auto;background:#fff;padding:12px;border-radius:8px}}
.hidden{{display:none}}
.note{{border-left:3px solid var(--accent);padding:10px 14px;background:var(--code-bg);
      border-radius:0 8px 8px 0;font-size:13.5px;color:var(--muted);margin:16px 0}}
.note b{{color:var(--ink)}}
.ok{{color:var(--ok);font-weight:600}}
footer{{color:var(--muted);font-size:12.5px;text-align:center;margin-top:28px}}
</style></head><body><div class="wrap">
<header><h1>Bitme Cosigner</h1><span class="net{mainnet_badge}">{network}</span></header>
<p class="sub"><span class="ok">Running.</span> This service holds one of three keys and co-signs
only when your policy allows. It can never spend on its own.</p>

<div class="card">
  <h2>Status</h2>
  <div class="kv"><span>Version</span><span>{version}</span></div>
  <div class="kv"><span>Network</span><span>{network}</span></div>
  <div class="kv"><span>Policy version</span><span>{policy_version}</span></div>
  <div class="kv"><span>Recovery timelock</span><span>{timelock} blocks (~{timelock_days} days)</span></div>
  <div class="kv"><span>First receive address</span><span>{first_address}</span></div>
</div>

<div class="card">
  <h2>Wallet descriptor</h2>
  <p>What your coordinator needs in order to know this wallet. Contains no private keys - safe to
  store as plain text, and worth keeping a copy: your three keys alone cannot rebuild the wallet
  without it.</p>
  <div class="tabs">{tabs}</div>
  <div class="note"><b>Start with Combined.</b> It carries receive and change in one descriptor
  using <code>&lt;0;1&gt;</code> (BIP389). If your wallet says the data doesn't match a supported
  format, it can't read multipath - switch to <b>Receive only</b>, and add <b>Change only</b> if it
  asks for a second descriptor. All three describe the same wallet.</div>
  {panes}
</div>

<div class="card">
  <h2>API</h2>
  <p>Everything else happens over HTTP. <code>GET /health</code>, <code>POST /inspect</code>,
  <code>POST /sign_psbt</code>, <code>GET /sign_psbt/{{id}}</code>, <code>POST /veto/{{id}}</code>,
  <code>GET|POST /policy</code>, <code>GET|POST /freeze</code>, <code>POST /unfreeze</code>.</p>
  <div class="note"><b>POST /freeze is deliberately unauthenticated.</b> It's the "my phone was
  just stolen" button and has to work in a hurry. Freezing can only cause denial of service, which
  is strictly better than theft.</div>
</div>

<footer>Two signatures move funds. This box only ever holds one of them.</footer>
</div>
<script>
document.querySelectorAll('.tab').forEach(t => t.onclick = () => {{
  document.querySelectorAll('.tab').forEach(x => x.classList.toggle('on', x === t));
  document.querySelectorAll('.pane').forEach(p => p.classList.toggle('hidden', p.id !== 'p-' + t.dataset.t));
}});
</script>
</body></html>"#,
        version = env!("CARGO_PKG_VERSION"),
        timelock = wallet.timelock_blocks,
        timelock_days = wallet.timelock_blocks / 144,
    )
}
