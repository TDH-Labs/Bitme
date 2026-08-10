// Drives the setup wizard's browser code end to end under jsdom, with the HTTP API stubbed.
//
// This exists because the wizard is the one part of this service with no other coverage. The
// Rust behind it is tested thoroughly; the ~900 lines of JavaScript that collect three xpubs,
// gate on device compatibility and post the config are not exercised by `cargo test` at all -
// and they sit directly in front of key generation. A typo in a selector or a renamed state
// field fails silently in a browser and produces a wizard that half works.
//
// Deliberately not a screenshot tool. It asserts behaviour: that the compatibility gate blocks a
// known-broken pairing and releases only on acknowledgement, that validation fires, and that the
// payload finally posted to /api/finish carries what the operator actually entered.
//
//   node --test tests/wizard_smoke.mjs
//
// jsdom is the only dependency and it is not vendored - install it wherever you run this:
//   npm install jsdom

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { JSDOM } from "jsdom";

const HERE = dirname(fileURLToPath(import.meta.url));
const HTML = readFileSync(join(HERE, "..", "src", "setup.html"), "utf8");

const TPUB_A =
  "tpubDDwf2gdFxFahr9RUtDQCuZmsx34CfdZ7RALAirwC2FGeLBzW1TDiEpqFeRdxLdZD7rfsbZHYwSaT6CLM3TAcYRw6xfRv4U6KCQt4Zuhvjkz";
const TPUB_B =
  "tpubDEXiq2SVhhqALktxfVFgj3C9M3T2G7xL11iezYg2LJAf245YkNyqp2K9TrvHABDCp2232k34UegU4aKEtUZNigit8EEqoLNe2JKMzMiLwYq";

/// The bundled compatibility matrix, trimmed to what the wizard reads.
const MATRIX = {
  schema_version: 1,
  revision: "test",
  hardware: [
    { id: "coldcard", label: "Coldcard (Mk4 / Q)", signs_miniscript: true, signs_older: true, signs_message: true, verified: "vendor-docs", notes: null },
    { id: "satochip", label: "Satochip", signs_miniscript: true, signs_older: true, signs_message: true, verified: "unverified", notes: "No coordinator drives it." },
  ],
  coordinator: [
    { id: "bitcoin-keeper", label: "Bitcoin Keeper", registers_miniscript: true, drives: ["coldcard"], holds_mobile_key: true, verified: "release-notes", notes: null },
  ],
};

/// Mirrors what `compat::resolve` returns for the two pairings above, so the wizard is driven
/// against the same shapes the real endpoint produces.
function resolveCompat(body) {
  const blocked = body.hardware === "satochip";
  const paths = ["Everyday spending", "Changing spending limits, and unfreezing",
                 "Recovery if this server is lost", "Recovery if the hardware key is lost"]
    .map((label, i) => ({
      path: "p" + i,
      label,
      verdict: blocked && i !== 3 ? "blocked" : "ok",
      gaps: [],
    }));
  const resolution = {
    hardware: body.hardware,
    coordinator: body.coordinator,
    paths,
    overall: blocked ? "blocked" : "ok",
    any_unverified: blocked,
    caveats: [],
  };
  return {
    resolution,
    acknowledgement: blocked
      ? "Everyday spending: no listed app can both track this descriptor and sign with this device\n\nIf you fund this wallet you may be unable to spend from it until software support changes."
      : null,
    options: MATRIX.hardware.map((h) => ({
      id: h.id,
      label: h.label,
      verdict: h.id === "satochip" ? "blocked" : "ok",
      notes: h.notes,
      summary: null,
    })).sort((a, b) => (a.verdict === "ok" ? -1 : 1)),
  };
}

/// Boots the wizard with a stubbed API and returns handles for driving it.
///
/// The stub is installed via `beforeParse`, not after construction: the wizard calls its own
/// `boot()` at script-parse time, so anything assigned afterwards is already too late and the
/// page renders its "couldn't load setup" state instead.
async function boot() {
  const calls = [];
  let window;
  const dom = new JSDOM(HTML, {
    runScripts: "dangerously",
    pretendToBeVisual: true,
    beforeParse(w) {
      window = w;
      w.fetch = makeFetch(calls);
    },
  });
  void dom;

  // The wizard boots on its own; give the async boot() a chance to settle.
  await settle(window);
  return { window, doc: window.document, calls };
}

function makeFetch(calls) {
  return async (path, init) => {
    const body = init && init.body ? JSON.parse(init.body) : undefined;
    calls.push({ path, body });
    const reply = (obj) => ({ ok: true, status: 200, text: async () => JSON.stringify(obj) });

    switch (path) {
      case "/api/state":
        return reply({ network: "signet", configured: false,
                       default_derivation_path: "48h/1h/0h/2h",
                       default_timelock_blocks: 12960, bitcoind_rpc_url: "http://node:38332" });
      case "/api/compat":
        return reply(MATRIX);
      case "/api/compat/resolve":
        return reply(resolveCompat(body));
      case "/api/validate-key":
        // Mirrors the server: an 8-hex fingerprint and a tpub are required.
        if (!/^[0-9a-f]{8}$/i.test(body.fingerprint) || !body.xpub.startsWith("tpub")) {
          return { ok: false, status: 400, text: async () => JSON.stringify({ error: "that fingerprint is not 8 hex characters" }) };
        }
        return reply({ ok: true });
      case "/api/server-key":
        return reply({
          mixed_user_entropy: Boolean(body && body.user_entropy),
          master_fingerprint: "56c4fac3", derivation_path: "48h/1h/0h/2h", xpub: "tpubSERVER",
          key_expression: "[56c4fac3/48'/1'/0'/2']tpubSERVER",
          key_expression_qr_svg: "<svg/>", import_json: "{}",
        });
      case "/api/finish":
        return reply({
          descriptor: "wsh(thresh(2,...))", receive_descriptor: "wsh(...)", change_descriptor: "wsh(...)",
          first_address: "tb1qexample", server_fingerprint: "56c4fac3", config_path: "/data/config/wallet.toml",
          api_token: "deadbeef".repeat(8),
          nostr_npub: body && body.nostr ? "npub1service" : undefined,
          descriptor_qr_svg: "<svg/>", receive_qr_svg: "<svg/>", change_qr_svg: "<svg/>",
        });
      default:
        throw new Error("unstubbed endpoint: " + path);
    }
  };
}

const settle = (window, ticks = 12) =>
  new Promise((resolve) => {
    let n = 0;
    const tick = () => (++n >= ticks ? resolve() : window.setTimeout(tick, 0));
    window.setTimeout(tick, 0);
  });

const $ = (doc, sel) => doc.querySelector(sel);
const text = (doc) => doc.getElementById("panel").textContent;

async function click(window, el) {
  el.dispatchEvent(new window.Event("click", { bubbles: true }));
  await settle(window);
}

async function setValue(window, el, value) {
  el.value = value;
  el.dispatchEvent(new window.Event("input", { bubbles: true }));
  el.dispatchEvent(new window.Event("change", { bubbles: true }));
  await settle(window);
}

test("the wizard boots and shows the welcome step", async () => {
  const { window, doc } = await boot();
  assert.match(text(doc), /Before you start/);
  assert.equal(doc.getElementById("net").textContent, "signet");
  window.close();
});

test("compatibility gate blocks a known-broken pairing until acknowledged", async () => {
  const { window, doc } = await boot();
  await click(window, $(doc, "#n")); // leave welcome -> device step

  assert.match(text(doc), /Which devices are you using/,
    "the device step must come before any key entry");

  // Coldcard resolves clean: Continue is live and there is no checkbox.
  const contBtn = () => doc.getElementById("n");
  assert.equal(contBtn().disabled, false, "a supported pairing must not be gated");
  assert.equal(doc.getElementById("ack"), null, "nothing to acknowledge when it works");

  // Switch to the blocked device.
  const satochip = [...doc.querySelectorAll('input[name="hw"]')].find((r) => r.value === "satochip");
  assert.ok(satochip, "every device must be listed, including unusable ones");
  satochip.checked = true;
  await setValue(window, satochip, "satochip");

  assert.equal(contBtn().disabled, true, "a blocked pairing must not be able to continue");
  const ack = doc.getElementById("ack");
  assert.ok(ack, "a blocked pairing must offer an explicit acknowledgement");
  assert.match(text(doc), /may be unable to spend/,
    "the gate must state the real consequence, not a softened one");
  assert.doesNotMatch(text(doc), /daily limit/,
    "must never imply this is only about spends over a limit");

  // Ticking it releases the gate - blocked is overridable, not fatal.
  ack.checked = true;
  await setValue(window, ack, "on");
  assert.equal(contBtn().disabled, false, "acknowledgement must unblock");
  window.close();
});

test("a full run posts everything the operator entered", async () => {
  const { window, doc, calls } = await boot();
  await click(window, $(doc, "#n")); // welcome -> devices
  await click(window, $(doc, "#n")); // devices -> hardware key (coldcard is clean)

  // --- hardware key: a bad fingerprint must be refused before it can advance
  assert.match(text(doc), /hardware key/i);
  await setValue(window, doc.getElementById("fp"), "nothex!!");
  await setValue(window, doc.getElementById("xpub"), TPUB_A);
  await click(window, $(doc, "#n"));
  assert.match(text(doc), /hardware key/i, "an invalid fingerprint must not advance the wizard");

  await setValue(window, doc.getElementById("fp"), "4ba43603");
  await click(window, $(doc, "#n"));

  // --- mobile key
  await setValue(window, doc.getElementById("fp"), "8dfc9b34");
  await setValue(window, doc.getElementById("xpub"), TPUB_B);
  await click(window, $(doc, "#n"));

  // --- server key, with operator-supplied entropy
  const dice = "4 2 6 1 3 5 5 2 6 1 4 3 2 5 1 6 3 4 2 5 1 6 4 3 6 2";
  await setValue(window, doc.getElementById("uent"), dice);
  await click(window, doc.getElementById("gen"));
  const genCall = calls.find((c) => c.path === "/api/server-key");
  assert.equal(genCall.body.user_entropy, dice, "typed entropy must actually reach the server");
  assert.match(text(doc), /OS CSPRNG \+ your own randomness/,
    "the UI must report which entropy source was used");
  await click(window, doc.getElementById("n"));

  // --- limits (defaults are fine)
  await click(window, doc.getElementById("n"));

  // --- hold window + escape address
  const escape = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
  await setValue(window, doc.getElementById("rwl"), escape + "\n");
  await setValue(window, doc.getElementById("ntfy"), "https://ntfy.sh/test-topic");
  await click(window, doc.getElementById("n"));

  // --- review, then create
  assert.match(text(doc), /Review/);
  await click(window, doc.getElementById("n"));

  const finish = calls.find((c) => c.path === "/api/finish");
  assert.ok(finish, "the wizard must have posted the config");
  assert.equal(finish.body.hardware.fingerprint, "4ba43603");
  assert.equal(finish.body.hardware.xpub, TPUB_A);
  assert.equal(finish.body.mobile.fingerprint, "8dfc9b34");
  assert.deepEqual(finish.body.recovery_destination_whitelist, [escape],
    "the escape address must survive the trailing newline and reach the server");
  assert.equal(finish.body.ntfy_url, "https://ntfy.sh/test-topic");
  assert.ok(finish.body.timelock_blocks > 0);

  // --- final screen shows the descriptor and the API token
  assert.match(text(doc), /wsh\(thresh/, "the descriptor must be shown");
  assert.match(text(doc), /tb1qexample/, "the first address must be shown for cross-checking");
  assert.match(text(doc), /deadbeef/, "the API token must be shown once");
  window.close();
});

test("the Nostr transport is off unless asked for, and validated when it is", async () => {
  const { window, doc, calls } = await boot();
  await click(window, $(doc, "#n"));
  await click(window, $(doc, "#n"));
  await setValue(window, doc.getElementById("fp"), "4ba43603");
  await setValue(window, doc.getElementById("xpub"), TPUB_A);
  await click(window, $(doc, "#n"));
  await setValue(window, doc.getElementById("fp"), "8dfc9b34");
  await setValue(window, doc.getElementById("xpub"), TPUB_B);
  await click(window, $(doc, "#n"));
  await click(window, doc.getElementById("gen"));
  await click(window, doc.getElementById("n"));
  await click(window, doc.getElementById("n"));

  // Hidden until enabled, so it cannot be filled in by accident.
  assert.ok(doc.getElementById("nostrfields").classList.contains("hidden"));
  await setValue(window, doc.getElementById("ntfy"), "https://ntfy.sh/test-topic");

  const nostrOn = doc.getElementById("nostron");
  nostrOn.checked = true;
  await setValue(window, nostrOn, "on");
  assert.equal(doc.getElementById("nostrfields").classList.contains("hidden"), false,
    "ticking the box must reveal the fields");

  // Enabled with an empty allowlist must not advance: an allowlist nobody is on accepts
  // requests from nobody, which is a slower way of writing "disabled".
  await setValue(window, doc.getElementById("nrelays"), "wss://relay.damus.io");
  await click(window, doc.getElementById("n"));
  assert.match(text(doc), /at least one relay and at least one npub/,
    "an empty npub allowlist must be refused, not silently accepted");

  await setValue(window, doc.getElementById("nnpubs"), "npub1phone\nnpub1laptop\n");
  await click(window, doc.getElementById("n"));
  assert.match(text(doc), /Review/);
  assert.match(text(doc), /2 allowed device/, "the review must say what was configured");
  await click(window, doc.getElementById("n"));

  const finish = calls.find((c) => c.path === "/api/finish");
  assert.deepEqual(finish.body.nostr, {
    relays: ["wss://relay.damus.io"],
    allowed_npubs: ["npub1phone", "npub1laptop"],
  });
  // The wizard must never send a secret key - the box generates its own.
  assert.equal(JSON.stringify(finish.body).includes("nsec"), false,
    "no nsec may ever be sent from the browser");
  window.close();
});

test("no blank whitelist entry is sent when the escape address is left empty", async () => {
  const { window, doc, calls } = await boot();
  await click(window, $(doc, "#n"));
  await click(window, $(doc, "#n"));
  await setValue(window, doc.getElementById("fp"), "4ba43603");
  await setValue(window, doc.getElementById("xpub"), TPUB_A);
  await click(window, $(doc, "#n"));
  await setValue(window, doc.getElementById("fp"), "8dfc9b34");
  await setValue(window, doc.getElementById("xpub"), TPUB_B);
  await click(window, $(doc, "#n"));
  await click(window, doc.getElementById("gen"));
  await click(window, doc.getElementById("n"));
  await click(window, doc.getElementById("n"));
  await setValue(window, doc.getElementById("ntfy"), "https://ntfy.sh/test-topic");
  await click(window, doc.getElementById("n"));
  await click(window, doc.getElementById("n"));

  const finish = calls.find((c) => c.path === "/api/finish");
  assert.equal(finish.body.recovery_destination_whitelist, null,
    "an empty textarea must mean no whitelist, never a list containing an empty string");
  window.close();
});
