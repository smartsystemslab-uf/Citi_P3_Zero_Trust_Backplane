"use strict";
/* ZT Console front end. No framework, no inline styles, no innerHTML: every value is added as text.
   It holds no protection logic: runs, builds and checks go through the real zt-adk command. */

// ------------------------------------------------------------------ helpers
const $view = document.getElementById("view");
// Per-tab storage: survives a page reload, is not shared with other tabs, and is optional (it can be blocked).
const tabStore = {
  get(key) { try { return JSON.parse(sessionStorage.getItem(`zt-${key}`)); } catch (e) { return null; } },
  set(key, value) { try { sessionStorage.setItem(`zt-${key}`, JSON.stringify(value)); } catch (e) { /* storage may be blocked */ } },
};
const S = { status: null, index: Number.isInteger(tabStore.get("profile")) ? tabStore.get("profile") : 0, names: null };
let AUDIT_PAGE = 300;                                    // records per page on the Audit page (the browser test lowers it)
let timers = [];

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v === true) el.setAttribute(k, "");
    else el.setAttribute(k, v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  if (attrs && typeof attrs.class === "string" && /\b(tablewrap|svgwrap)\b/.test(attrs.class)) {   // scrollable regions must be reachable by keyboard
    el.setAttribute("tabindex", "0"); el.setAttribute("role", "region"); el.setAttribute("aria-label", `${attrs.class.includes("svgwrap") ? "Agent map" : "Table"} ${++regionCount} (scrollable)`);
  }
  if (tag === "tr" && attrs && attrs.onclick) {          // clickable rows are reachable and operable from the keyboard
    el.setAttribute("tabindex", "0");
    el.addEventListener("keydown", (e) => { if (e.key === "Enter") el.click(); });
  }
  return el;
}
let regionCount = 0;
const SVGNS = "http://www.w3.org/2000/svg";
function sv(tag, attrs, ...kids) {
  const el = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) { if (k.startsWith("on")) el.addEventListener(k.slice(2), v); else el.setAttribute(k, v); }
  for (const kid of kids.flat()) if (kid != null) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return el;
}
// Element.append stringifies arrays ("[object HTMLDivElement]"). Pages build lists of nodes as arrays, so flatten them here once.
const nativeAppend = Element.prototype.append;
Element.prototype.append = function (...kids) { return nativeAppend.apply(this, kids.flat(Infinity).filter((k) => k != null && k !== false)); };

async function api(path, opts = {}) {
  const res = await fetch(path, {
    method: opts.method || "GET",
    headers: { "Content-Type": "application/json", "X-ZT-Console": "1", "X-ZT-Profile": String(S.index) },
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch (e) { /* not JSON */ }
  if (!res.ok) {
    const err = new Error((data && data.error) || (data && data.detail) || res.statusText);
    err.status = res.status; err.unavailable = !!(data && data.unavailable);
    throw err;
  }
  return data;
}
// A cell that starts with = + - @ (or a tab/CR) is run as a formula by spreadsheet programs; test messages are hostile text by design.
const csvSafe = (x) => (/^[=+\-@\t\r]/.test(String(x)) ? `'${x}` : String(x));
const fmtTime = (ts) => { if (!ts) return ""; const d = new Date(ts); return isNaN(d) ? String(ts) : d.toLocaleString(); };
const shortHash = (s) => (s ? String(s).slice(0, 12) : "");
const critChip = (c) => (c ? h("span", { class: `chip crit-${c}` }, c) : null);
const notice = (text, kind = "") => h("div", { class: `notice ${kind}` }, text);
// The page names its application in every request (X-ZT-Profile), so each browser tab has its own selection.
async function refreshStatus() {
  S.status = await api("/api/status");
  S.index = S.status.index;                              // the server falls back to the first profile for an unusable value
  tabStore.set("profile", S.index);
  return S.status;
}
const names = () => S.names || { approver: "alice", secondary: "bob" };
function setNames(setup) { S.names = { approver: (setup.approvers || [])[0] || "alice", secondary: (setup.secondaries || [])[0] || "bob" }; }
function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }
function stopTimers() { timers.forEach(clearInterval); timers = []; }
const LOG_WINDOW_NOTE = "The audit log is larger than 8 MB, so only its newest part is listed and counted here. 'Verify chain' still checks the whole file.";
const NOT_LOADED = "No built protection bundle for this application yet. Use 'Create keys' and 'Build bundle' in the Test Lab (or run 'zt-adk keys init' and 'zt-adk build'), then reload.";
function unavailable(err) { return err.unavailable ? notice(NOT_LOADED) : notice(err.message, "err"); }

// ------------------------------------------------------------------ shell
const MENU = [["dashboard", "Dashboard"], ["lab", "Test Lab"], ["learn", "Learn"], ["system", "System"], ["policies", "Policies"], ["audit", "Audit"], ["approvals", "Approvals"]];

function renderShell(active) {
  const top = document.getElementById("top"); clear(top);
  const profiles = (S.status && S.status.profiles) || [];
  const pick = h("select", { "aria-label": "Application", onchange: async () => { S.index = Number(pick.value); await refreshStatus(); S.names = null; L.last = null; route(); } },
    profiles.map((p) => h("option", { value: p.index, selected: p.index === S.status.index }, `${p.label}${p.built ? "" : "  (not built)"}`)));
  const mark = sv("svg", { width: 26, height: 26, viewBox: "0 0 24 24", "aria-hidden": "true", focusable: "false" },
    sv("path", { d: "M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3z", fill: "none", stroke: "#ffffff", "stroke-width": 1.8, "stroke-linejoin": "round" }),
    sv("path", { d: "m8.5 12 2.5 2.5 4.5-5", fill: "none", stroke: "#ff7a4d", "stroke-width": 2, "stroke-linecap": "round", "stroke-linejoin": "round" }));
  top.append(h("div", { class: "brand" }, mark, h("span", null, "ZT Console")), h("p", null, "Run and test the Zero Trust Backplane"), h("span", { class: "grow" }),
    profiles.length ? h("label", { class: "who" }, "Application ", pick) : null);
  const menu = document.getElementById("menu"); clear(menu);
  const items = MENU;
  for (const [key, label] of items) {
    const a = h("a", { href: `#/${key}`, class: key === active ? "active" : "" }, label);
    if (key === "approvals") a.append(h("span", { class: "badge hidden", id: "appr-badge" }, "0"));
    menu.append(a);
  }
  if (S.status && S.status.configured) refreshBadge();
}
async function refreshBadge() {
  try {
    const n = (await api("/api/bp/approvals")).filter((a) => a.status === "pending").length;
    const b = document.getElementById("appr-badge");
    if (b) { b.textContent = String(n); b.classList.toggle("hidden", n === 0); }
  } catch (e) { /* optional */ }
}

// ------------------------------------------------------------------ router
const PAGES = { dashboard, lab, learn, system, policies, audit, approvals };
async function route() {
  stopTimers();
  const parts = (location.hash.slice(2) || "dashboard").split("/");
  let name = parts[0] in PAGES ? parts[0] : "dashboard";
  if (!S.status) { try { await refreshStatus(); } catch (e) { S.status = { configured: false, profiles: [], index: 0 }; } }
  renderShell(name);
  clear($view); $view.classList.toggle("pad", name !== "lab");
  const label = (MENU.find((m) => m[0] === name) || ["", "ZT Console"])[1];
  document.title = `${label} | ZT Console`;
  const loader = h("p", { class: "muted loading" }, h("span", { class: "spinner" }), "Loading...");
  $view.append(loader);
  try { await PAGES[name]($view, decodeURIComponent(parts.slice(1).join("/"))); } catch (e) { $view.classList.add("pad"); $view.append(unavailable(e)); }
  finally { loader.remove(); }
  window.scrollTo(0, 0);
}
// every table scrolls inside its own region on narrow screens (also for tables added later, such as run results)
new MutationObserver(() => {
  $view.querySelectorAll("table").forEach((t) => { if (!t.closest(".tablewrap")) { const w = h("div", { class: "tablewrap" }); t.replaceWith(w); w.append(t); } });
}).observe($view, { childList: true, subtree: true });
window.addEventListener("hashchange", route);
window.addEventListener("DOMContentLoaded", route);

// ------------------------------------------------------------------ shared renderers
function eventCard(e) {
  const card = h("div", { class: `ev out-${e.outcome}` },
    h("div", { class: "head" }, h("span", { class: "seq" }, `#${e.seq}`), h("span", { class: "tag" }, e.boundary), h("span", { class: `tag out-${e.outcome}` }, e.outcome),
      h("span", { class: "muted" }, fmtTime(e.ts)), e.caller || e.target ? h("span", { class: "muted mono" }, `${e.caller || ""} → ${e.target || ""}`) : null),
    h("div", { class: "text" }, e.text));
  (e.rules || []).forEach((r) => card.append(h("div", { class: "rule" }, h("span", { class: "mono" }, r.id), r.text ? ` – ${r.text}` : "")));
  card.append(h("details", null, h("summary", null, "Record"), h("pre", null, JSON.stringify(e.raw, null, 2))));
  return card;
}
function approvalCard(a, after) {
  const cls = a.status === "pending" ? "held" : a.status === "denied" ? "denied" : "allowed";
  const decisionLine = Object.entries(a.decisions || {}).map(([k, d]) => `${k}: ${d.decision} by ${d.issuer}`).join("; ");
  const card = h("div", { class: `ev out-${cls}` },
    h("div", { class: "head" }, h("span", { class: "mono" }, a.approval_id), h("span", { class: `tag out-${cls}` }, a.status), h("b", null, `${a.agent}/${a.tool}`), h("span", { class: "muted" }, `expires ${fmtTime(a.expires_at)}`)),
    h("div", { class: "text" }, `Needs: ${a.purposes.join(" + ")}. Reason held: ${a.reason}`),
    h("div", { class: "small muted" }, `Request hash ${shortHash(a.request_hash)}…  Environment: ${a.environment || ""}${decisionLine ? "  Decisions: " + decisionLine : ""}`),
    h("details", { open: a.status === "pending" }, h("summary", null, "Exact arguments being approved"), h("pre", null, JSON.stringify(a.parameters, null, 2))));
  if (a.status === "pending") {
    if (S.status.dev_approve) {
      const who = h("input", { placeholder: "approver name", value: names().approver, size: 12, "aria-label": "Approver name" });
      const sec = h("input", { type: "checkbox", id: `sec-${a.approval_id}`, onchange: () => { who.value = sec.checked ? names().secondary : names().approver; } });
      const msg = h("span", { class: "small" });
      const act = async (decision) => { try { await api(`/api/bp/approvals/${a.approval_id}/decision`, { method: "POST", body: { decision, approver: who.value.trim(), secondary: sec.checked } }); msg.textContent = "Signed."; after && after(); } catch (e) { msg.textContent = e.message; } };
      card.append(h("div", { class: "row tight" }, who, h("label", { for: sec.id }, sec, " secondary"), h("button", { class: "small", onclick: () => act("approve") }, "Approve"), h("button", { class: "small danger", onclick: () => act("deny") }, "Deny"), msg),
        h("div", { class: "note" }, "Developer mode: signs with a local approver key. In production approver keys stay on approver devices."));
    } else {
      card.append(h("div", { class: "small" }, "Approve from a terminal: ", h("code", null, `zt-adk approvals approve ${a.approval_id} --approver NAME`)));
    }
  }
  return card;
}
function renderRun(target, r) {
  clear(target);
  if (!r) { target.append(h("p", { class: "muted" }, "No run loaded. Run a test on the left, or pick an earlier run above.")); return; }
  target.append(h("div", { class: "muted" }, `${r.id || ""}  ${fmtTime(r.ts)}${r.name ? "  • " + r.name : ""}  • role: ${r.role || "(none)"}`),
    h("div", { class: `verdict ${r.verdict.state}` }, h("b", null, r.verdict.title), h("div", null, r.verdict.text)));
  r.messages.forEach((m, i) => target.append(h("div", { class: "small" }, h("b", null, `Turn ${i + 1}: `), h("span", { class: "pre-wrap" }, m))));
  if (r.checks) {
    target.append(h("h3", null, `Evaluation: ${r.passed ? "PASSED" : "FAILED"}`),
      h("table", null, r.checks.map((c) => h("tr", null, h("td", { class: c.ok ? "pass" : "fail" }, c.ok ? "✓ pass" : "✗ fail"), h("td", null, c.name), h("td", { class: "muted" }, c.detail)))));
  }
  if (r.answer) target.append(h("h3", null, `Answer${r.answer_agent ? " from " + r.answer_agent : ""}`), h("div", { class: "answer" }, r.answer));
  target.append(h("h3", null, `What each boundary decided (${r.events.filter((e) => e.event !== "ENGINE_START").length} records)`));
  r.events.filter((e) => e.event !== "ENGINE_START").forEach((e) => target.append(eventCard(e)));
  target.append(h("details", null, h("summary", null, "Raw command output"), h("pre", null, r.output || "(none)")));
}

// ------------------------------------------------------------------ Test Lab (editor | trace viewer)
const L = { turns: [""], name: "", role: "", expect: { state: "", boundary: "", rule: "", answer_contains: "", answer_not_contains: "" },
  last: null, results: [], batch: "", running: false, autorun: null, autoApprove: false, setupMsg: null, stopRequested: false,
  approverName: "alice", secondaryName: "bob" };
// The editor draft and the batch results are kept per tab, so a page reload does not lose them.
(function restoreDraft() {
  const d = tabStore.get("draft");
  if (!d || typeof d !== "object") return;
  const str = (x, n) => (typeof x === "string" ? x.slice(0, n) : "");
  if (Array.isArray(d.turns) && d.turns.length && d.turns.length <= 10) L.turns = d.turns.map((t) => str(t, 4000));
  L.name = str(d.name, 120); L.role = str(d.role, 40); L.batch = str(d.batch, 20000);
  for (const k of Object.keys(L.expect)) L.expect[k] = str((d.expect || {})[k], 200);
  if (Array.isArray(d.results)) L.results = d.results.filter((r) => r && typeof r.name === "string" && r.state !== "running").slice(0, 200);
  L.approverName = str(d.approverName, 40) || "alice"; L.secondaryName = str(d.secondaryName, 40) || "bob"; L.autoApprove = d.autoApprove === true;
})();
let draftTimer = null;
function saveDraft() {
  clearTimeout(draftTimer);
  draftTimer = setTimeout(() => tabStore.set("draft", { turns: L.turns, name: L.name, role: L.role, expect: L.expect, batch: L.batch,
    results: L.results.filter((r) => r.state !== "running"), approverName: L.approverName, secondaryName: L.secondaryName, autoApprove: L.autoApprove }), 200);
}
document.addEventListener("input", saveDraft);
document.addEventListener("change", saveDraft);
async function stopRun() {
  L.stopRequested = true;
  try { await api("/api/bp/cancel", { method: "POST", body: {} }); } catch (e) { /* nothing was running */ }
}
const STATES = [["", "(no expectation)"], ["allowed", "allowed"], ["completed", "completed (allowed or flagged)"], ["flagged", "flagged"], ["blocked", "blocked"], ["held", "held for approval"]];
const BOUNDS = ["", "Input", "Route", "Tool", "Tool result", "Model", "Output", "Approval", "Workflow", "Identity"];
const cleanExpect = () => Object.fromEntries(Object.entries(L.expect).filter(([, v]) => v && v.trim()).map(([k, v]) => [k, v.trim()]));
const turnsText = (m) => m.join("  |  ");
const expectText = (e) => Object.entries(e || {}).map(([k, v]) => `${k}=${v}`).join(", ") || "none";

async function lab(v) {
  const st = S.status;
  let scen = [], cases = [], runs = [], rules = [], setup = {}, ov = null;
  [scen, cases, runs, setup] = await Promise.all([api("/api/bp/scenarios").catch(() => []), api("/api/bp/cases").catch(() => []), api("/api/bp/runs").catch(() => []), api("/api/bp/setup").catch(() => ({}))]);
  if (st.configured) {
    ov = await api("/api/bp/overview").catch(() => null);
    const p = await api("/api/bp/policies").catch(() => null);
    if (p) rules = p.files.flatMap((f) => f.rules.map((r) => r.id));
  }
  if (!L.last && runs.length) L.last = await api(`/api/bp/runs/${runs[0].id}`).catch(() => null);
  setNames(setup);

  // ---------------- left pane: test editor
  const left = h("div", { class: "pane" }), right = h("div", { class: "pane" });
  v.append(h("h1", { class: "sr-only" }, "Test Lab"));
  const view = h("div"), pending = h("div"), setupOut = h("div"), resultsBox = h("div");
  const runSel = h("select", { "aria-label": "Earlier runs" });

  const setupBtn = (label, action, disabled) => h("button", { class: "secondary small", disabled, onclick: async (ev) => {
    const b = ev.target; b.disabled = true; clear(setupOut); setupOut.append(h("span", { class: "spinner" }), `${label}... `, h("button", { class: "danger small", onclick: stopRun }, "Stop"));
    const body = action === "keys" ? { approver: L.approverName.trim() || "alice", secondary: L.secondaryName.trim() || "bob" } : {};
    try { const r = await api(`/api/bp/setup/${action}`, { method: "POST", body }); L.setupMsg = { label, ok: r.ok, exit: r.exit_code, output: r.output, stopped: r.cancelled }; }
    catch (e) { L.setupMsg = { label, ok: false, exit: "-", output: e.message }; }
    await refreshStatus(); route();
  } }, label);

  left.append(h("h2", null, "Test editor"),
    h("p", { class: "muted" }, "Messages are sent through the real zt-adk command, exactly as typed in a terminal. Nothing on this page decides anything."),
    h("fieldset", null, h("legend", null, "Application"),
      h("div", null, h("span", { class: `status ${setup.keys ? "ok" : "warn"}` }, setup.keys ? "keys ✓" : "keys missing"), " ", h("span", { class: `status ${st.configured ? "ok" : "warn"}` }, st.configured ? "bundle built ✓" : "bundle not built"), " ",
        ov ? h("span", { class: "muted" }, `${ov.app}: ${ov.counts.agents} agents, ${ov.counts.tools} tools, mode ${ov.mode}`) : null),
      h("div", null, setupBtn("Create keys", "keys", !setup.command || !st.profile), setupBtn("Build bundle", "build", !setup.keys || !setup.command), setupBtn("Check bundle", "check", !st.configured || !setup.command)), setupOut,
      setup.keys ? h("div", { class: "small muted" }, `Approvers on this machine: ${(setup.approvers || []).join(", ") || "none"}; second approver: ${(setup.secondaries || []).join(", ") || "none"}.`)
        : h("details", null, h("summary", null, "Approver names for Create keys (optional)"), h("div", { class: "row" },
          h("div", null, h("label", null, "Approver"), h("input", { value: L.approverName, maxlength: 40, "aria-label": "Approver name for new keys", oninput: (e) => { L.approverName = e.target.value; } })),
          h("div", null, h("label", null, "Second approver"), h("input", { value: L.secondaryName, maxlength: 40, "aria-label": "Second approver name for new keys", oninput: (e) => { L.secondaryName = e.target.value; } })))),
      st.configured ? null : notice(NOT_LOADED)),
    h("fieldset", null, h("legend", null, "Load a test"),
      h("select", { "aria-label": "Load a test", onchange: (ev) => { const [grp, id] = ev.target.value.split(":"); const src = (grp === "p" ? scen : cases).find((x) => x.id === id); if (src) { L.name = src.name; L.turns = [...src.messages]; L.role = src.role || ""; L.expect = { state: "", boundary: "", rule: "", answer_contains: "", answer_not_contains: "", ...(src.expect || {}) }; drawEditor(); editorNote.textContent = src.shows || ""; } } },
        h("option", { value: "" }, "(choose a preset or a saved test)"), scen.length ? h("optgroup", { label: "Presets" }, scen.map((s) => h("option", { value: `p:${s.id}` }, `${s.id}  ${s.name}`))) : null,
        cases.length ? h("optgroup", { label: "Saved tests" }, cases.map((c) => h("option", { value: `c:${c.id}` }, `${c.id}  ${c.name}`))) : null),
      h("div", { class: "note", id: "editor-note" }, "")));
  const editorNote = left.querySelector("#editor-note");
  if (L.setupMsg) { const m = L.setupMsg; setupOut.append(h("span", { class: `status ${m.ok ? "ok" : m.stopped ? "warn" : "err"}` }, `${m.label}: ${m.ok ? "ok" : m.stopped ? "stopped" : "failed (exit " + m.exit + ")"}`), h("details", { open: !m.ok }, h("summary", null, "Command output"), h("pre", null, m.output || "(none)"))); }

  const editor = h("div");
  left.append(editor);
  const dl = h("datalist", { id: "rules" }, rules.map((r) => h("option", { value: r })));
  const roleList = h("datalist", { id: "roles" }, ((ov && ov.roles) || []).map((r) => h("option", { value: r })));
  function drawEditor() {
    clear(editor); saveDraft();
    const name = h("input", { value: L.name, maxlength: 120, placeholder: "name (used when you save the test)", "aria-label": "Test name", oninput: (e) => { L.name = e.target.value; } });
    const role = h("input", { value: L.role, list: "roles", maxlength: 40, "aria-label": "End-user role", oninput: (e) => { L.role = e.target.value; } });
    const turns = h("div");
    L.turns.forEach((t, i) => turns.append(h("div", { class: "turn" }, h("span", { class: "n" }, i + 1),
      h("textarea", { rows: 2, maxlength: 4000, placeholder: i ? "next message in the same conversation" : "message to the application", "aria-label": `Turn ${i + 1}`, oninput: (e) => { L.turns[i] = e.target.value; } }, t),
      L.turns.length > 1 ? h("button", { class: "secondary small", title: "remove turn", onclick: () => { L.turns.splice(i, 1); drawEditor(); } }, "×") : null)));
    const exp = (key) => (e) => { L.expect[key] = e.target.value; };
    editor.append(
      h("div", { class: "row" }, h("div", null, h("label", null, "Name"), name), h("div", null, h("label", null, "End-user role (asserted by the front end)"), role)),
      h("fieldset", null, h("legend", null, "Conversation"), turns, h("button", { class: "secondary small", onclick: () => { if (L.turns.length < 10) { L.turns.push(""); drawEditor(); } } }, "+ Add turn")),
      h("fieldset", null, h("legend", null, "Expected outcome (optional)"),
        h("div", { class: "row" }, h("div", null, h("label", null, "Outcome"), h("select", { "aria-label": "Expected outcome", onchange: exp("state") }, STATES.map(([val, lbl]) => h("option", { value: val, selected: L.expect.state === val }, lbl)))),
          h("div", null, h("label", null, "Boundary involved"), h("select", { "aria-label": "Boundary involved", onchange: exp("boundary") }, BOUNDS.map((b) => h("option", { value: b, selected: L.expect.boundary === b }, b || "(any)"))))),
        h("label", null, "Rule that must fire"), h("input", { list: "rules", value: L.expect.rule, placeholder: "e.g. content.input.prompt-injection", oninput: exp("rule"), "aria-label": "Rule id" }),
        h("div", { class: "row" }, h("div", null, h("label", null, "Answer contains"), h("input", { "aria-label": "Answer contains", value: L.expect.answer_contains, oninput: exp("answer_contains") })), h("div", null, h("label", null, "Answer must not contain"), h("input", { "aria-label": "Answer must not contain", value: L.expect.answer_not_contains, oninput: exp("answer_not_contains") }))),
        h("div", { class: "note" }, "Leave everything empty to just look at what happens. With expectations the run is marked pass or fail.")),
      dl, roleList);
    const runBtn = h("button", { class: "accent", disabled: !st.can_run || L.running, onclick: () => doRun() }, "Run");
    const auto = h("input", { type: "checkbox", id: "auto-approve", checked: L.autoApprove && st.dev_approve, disabled: !st.dev_approve, onchange: (e) => { L.autoApprove = e.target.checked; } });
    editor.append(h("div", { class: "note" }, h("label", { for: "auto-approve", class: "inline" }, auto, " Approve held operations automatically while the run waits ", h("span", { class: "muted" }, st.dev_approve ? `(developer mode: signs with the local ${names().approver} / ${names().secondary} keys)` : "(needs --dev-approve)"))));
    editor.append(h("div", null, runBtn, h("button", { class: "secondary", onclick: saveCase }, "Save as test"), h("button", { class: "secondary", onclick: () => { L.name = ""; L.turns = [""]; L.expect = { state: "", boundary: "", rule: "", answer_contains: "", answer_not_contains: "" }; drawEditor(); } }, "Clear"), " ", h("span", { id: "run-state", class: "muted" })), pending);
  }
  drawEditor();

  const payload = () => ({ messages: L.turns.map((t) => t.trim()).filter(Boolean), role: L.role.trim(), name: L.name.trim(), expect: cleanExpect() });
  const setState = (node) => { const s = document.getElementById("run-state"); if (s) { clear(s); if (node) s.append(node); } };
  const signing = new Set();
  async function autoApprove(a) {
    const need = [["human_approval", names().approver, false], ["secondary_authorization", names().secondary, true]];
    for (const [purpose, who, sec] of need) {
      const key = `${a.approval_id}:${purpose}`;
      if (!a.purposes.includes(purpose) || (a.decisions || {})[purpose] || signing.has(key)) continue;
      signing.add(key);
      try { await api(`/api/bp/approvals/${a.approval_id}/decision`, { method: "POST", body: { decision: "approve", approver: who, secondary: sec, comment: "auto-approved by the console (developer mode)" } }); } catch (e) { /* shown on the card */ }
    }
  }
  async function loadPending(auto) {
    try {
      const list = (await api("/api/bp/approvals")).filter((a) => a.status === "pending");
      if (auto === true && S.status.dev_approve) list.forEach(autoApprove);
      clear(pending); if (list.length) pending.append(h("h3", null, "Waiting for approval"), list.map((a) => approvalCard(a, loadPending)));
    } catch (e) { /* ignore */ }
  }
  async function runOne(body, auto) {
    L.running = true; drawEditorKeepRunning();
    // not kept in `timers`: those are cleared whenever the user opens another page, which must not stop auto-approval of a run in progress
    const poll = setInterval(() => loadPending(auto), 1500);
    try { return await api("/api/bp/run", { method: "POST", body }); } finally { clearInterval(poll); L.running = false; clear(pending); }
  }
  function drawEditorKeepRunning() { setState(h("span", null, h("span", { class: "spinner" }), "Running (a critical operation waits for approval)... ", h("button", { class: "danger small", onclick: stopRun }, "Stop"))); }
  async function doRun() {
    const body = payload(); if (!body.messages.length) { setState(h("span", { class: "fail" }, "Enter at least one message.")); return; }
    L.stopRequested = false;
    try { const r = await runOne(body, L.autoApprove); L.last = r; await refreshRuns(); renderRun(view, r); setState(null); }
    catch (e) { setState(h("span", { class: "fail" }, e.message)); }
  }
  async function saveCase() {
    const body = payload(); if (!body.name) { setState(h("span", { class: "fail" }, "Give the test a name first.")); return; }
    try { await api("/api/bp/cases", { method: "POST", body }); route(); } catch (e) { setState(h("span", { class: "fail" }, e.message)); }
  }

  // ---------------- batch, saved tests, results
  const batchArea = h("textarea", { rows: 5, placeholder: "one message per line", "aria-label": "Batch messages", oninput: (e) => { L.batch = e.target.value; } }, L.batch);
  left.append(h("fieldset", null, h("legend", null, "Batch: many messages, one role, one expectation"), batchArea,
    h("div", { class: "note" }, "Uses the role and expected outcome above for every line. Each line is its own conversation."),
    h("button", { class: "secondary", disabled: !st.can_run, onclick: () => runList(L.batch.split("\n").map((s) => s.trim()).filter(Boolean).map((m) => ({ name: m.slice(0, 60), messages: [m], role: L.role.trim(), expect: cleanExpect() })), "batch") }, "Run batch")));
  const picked = new Set();
  const all = [...scen.map((s) => ({ ...s, key: `p:${s.id}` })), ...cases.map((c) => ({ ...c, key: `c:${c.id}` }))];
  left.append(h("fieldset", null, h("legend", null, "Saved tests and presets (campaign)"),
    all.length ? h("div", { class: "tablewrap" }, h("table", null, h("tr", null, ["", "Test", "Conversation", "Expected", ""].map((t) => h("th", null, t))),
      all.map((t) => h("tr", null, h("td", null, h("input", { type: "checkbox", "aria-label": `select ${t.name}`, onchange: (e) => (e.target.checked ? picked.add(t.key) : picked.delete(t.key)) })), h("td", null, h("b", null, t.id), " ", t.name),
        h("td", { class: "small" }, turnsText(t.messages)), h("td", { class: "small muted" }, expectText(t.expect)),
        h("td", null, t.preset ? null : h("button", { class: "danger small", onclick: async () => { await api(`/api/bp/cases/${t.id}`, { method: "DELETE" }); route(); } }, "delete")))))) : h("p", { class: "muted" }, "No tests yet. Load a preset or save your own."),
    h("button", { class: "secondary", disabled: !st.can_run || !all.length, onclick: () => runList(all.filter((t) => picked.has(t.key)), "selected") }, "Run selected"),
    h("button", { class: "secondary", disabled: !st.can_run || !all.length, onclick: () => runList(all, "all") }, "Run all"),
    h("div", { class: "note" }, "Tests run one after another. A preset that needs approval waits up to the profile's wait time unless you approve it.")),
    h("fieldset", null, h("legend", null, "Results"), resultsBox));

  function drawResults() {
    clear(resultsBox); saveDraft();
    if (!L.results.length) { resultsBox.append(h("p", { class: "muted" }, "Results of batches and campaigns appear here.")); return; }
    const done = L.results.filter((r) => r.state !== "running"), passed = done.filter((r) => r.passed === true).length,
      failed = done.filter((r) => r.passed === false).length, stopped = done.filter((r) => r.state === "cancelled" || r.state.startsWith("not run")).length, none = done.length - passed - failed - stopped;
    resultsBox.append(h("div", null, h("span", { class: `status ${failed ? "err" : "ok"}` }, `${passed} passed, ${failed} failed`), " ",
      stopped ? h("span", { class: "status warn" }, `${stopped} stopped`) : null, " ",
      none ? h("span", { class: "muted" }, ` ${none} without expectation`) : null, " ",
      h("button", { class: "secondary small", onclick: () => exportResults("json") }, "Export JSON"), h("button", { class: "secondary small", onclick: () => exportResults("csv") }, "Export CSV"), h("button", { class: "secondary small", onclick: () => exportResults("md") }, "Export report"), h("button", { class: "secondary small", onclick: () => { L.results = []; drawResults(); } }, "Clear")),
      h("div", { class: "tablewrap" }, h("table", null, h("tr", null, ["Test", "Outcome", "Result", "Checks failed", ""].map((t) => h("th", null, t))),
        L.results.map((r) => h("tr", { class: r.run_id ? "clickable" : "", onclick: () => r.run_id && openRun(r.run_id) }, h("td", null, r.name), h("td", null, r.state === "running" ? h("span", { class: "spinner" }) : r.state),
          h("td", { class: r.passed === true ? "pass" : r.passed === false ? "fail" : "pending" }, r.state === "running" ? "running" : r.passed === true ? "PASS" : r.passed === false ? "FAIL" : r.state === "cancelled" ? "STOPPED" : "-"),
          h("td", { class: "small" }, (r.failed || []).join("; ")), h("td", { class: "small muted nowrap" }, r.run_id ? "trace →" : ""))))));
  }
  async function runList(list, label) {
    if (!list.length) return;
    L.results = list.map((t) => ({ name: t.name || t.messages[0].slice(0, 60), state: "running" })); drawResults();
    L.stopRequested = false;
    for (let i = 0; i < list.length; i++) {
      const t = list[i];
      if (L.stopRequested) { for (let j = i; j < list.length; j++) L.results[j] = { name: L.results[j].name, state: "not run (stopped)" }; drawResults(); break; }
      try {
        if (t.auto_approve && !S.status.dev_approve) { L.results[i] = { name: L.results[i].name, state: "skipped (needs --dev-approve)" }; drawResults(); continue; }
        const r = await runOne({ messages: t.messages, role: t.role || "", name: t.name || "", expect: t.expect || {} }, !!t.auto_approve);
        L.results[i] = { name: L.results[i].name, state: r.verdict.state, passed: r.verdict.state === "cancelled" ? undefined : r.passed, failed: (r.checks || []).filter((c) => !c.ok).map((c) => c.name), run_id: r.run_id, messages: t.messages, role: t.role || "" };
        L.last = r;
      } catch (e) { L.results[i] = { name: L.results[i].name, state: "error", passed: false, failed: [e.message] }; }
      drawResults(); setState(null);
    }
    await refreshRuns(); renderRun(view, L.last);
  }
  function exportResults(kind) {
    if (kind === "md") {
      const when = new Date().toLocaleString(), ok = L.results.filter((r) => r.passed === true).length;
      const line = (r) => `| ${r.name.replace(/\|/g, "/")} | ${(turnsText(r.messages || []) || "").replace(/\|/g, "/")} | ${r.state} | ${r.passed === true ? "pass" : r.passed === false ? "FAIL" : r.state === "cancelled" ? "stopped" : "-"} |`;
      const md = [`# ZT Backplane test report`, ``, `Application: ${(S.status.profiles[S.status.index] || {}).app || ""}  `, `Generated: ${when}  `, `Result: ${ok} of ${L.results.length} passed`, ``, `| Test | Conversation | Outcome | Result |`, `|---|---|---|---|`, ...L.results.map(line), ``].join("\n");
      const a = h("a", { href: URL.createObjectURL(new Blob([md], { type: "text/markdown" })), download: "zt-test-report.md" }); document.body.append(a); a.click(); a.remove(); return;
    }
    const rows = L.results.map((r) => ({ test: r.name, conversation: turnsText(r.messages || []), role: r.role || "", outcome: r.state, passed: r.passed === undefined ? "" : String(r.passed), failed_checks: (r.failed || []).join("; ") }));
    const text = kind === "json" ? JSON.stringify(rows, null, 2) : [Object.keys(rows[0]).join(","), ...rows.map((r) => Object.values(r).map((x) => `"${csvSafe(x).replace(/"/g, '""')}"`).join(","))].join("\n");
    const a = h("a", { href: URL.createObjectURL(new Blob([text], { type: kind === "json" ? "application/json" : "text/csv" })), download: `zt-test-results.${kind}` });
    document.body.append(a); a.click(); a.remove();
  }
  drawResults();

  // ---------------- right pane: trace viewer
  async function refreshRuns() {
    runs = await api("/api/bp/runs").catch(() => []); clear(runSel);
    runSel.append(h("option", { value: "" }, runs.length ? "(choose an earlier run)" : "(no runs yet)"),
      runs.map((r) => h("option", { value: r.id, selected: !!(L.last && L.last.id === r.id) }, `${fmtTime(r.ts)}  ${r.name || r.messages[0].slice(0, 36)}  ${r.state}${r.passed === true ? " ✓" : r.passed === false ? " ✗" : ""}`)));
  }
  async function openRun(id) { try { L.last = await api(`/api/bp/runs/${id}`); renderRun(view, L.last); right.scrollIntoView({ behavior: "smooth" }); } catch (e) { clear(view); view.append(notice(e.message, "err")); } }
  right.append(h("h2", null, "Trace viewer"), h("label", null, "Run"), runSel,
    h("div", null, h("button", { class: "secondary", onclick: async () => { await refreshRuns(); } }, "Refresh"), h("button", { onclick: () => runSel.value && openRun(runSel.value) }, "Load trace"), h("button", { class: "secondary", onclick: () => { if (L.last) window.location.hash = "#/audit"; } }, "Open in audit log")), view);
  await refreshRuns();
  renderRun(view, L.last);
  v.append(h("div", { class: "panes" }, left, right));
  if (L.autorun && st.can_run) { const mode = L.autorun; L.autorun = null; runList(mode === "presets" ? scen.map((x) => ({ ...x })) : all, mode); }
}

// ------------------------------------------------------------------ Learn
function learn(v) {
  const BOUNDARIES = [
    ["Input", "Session present, end-user role known, prompt-injection phrases, secrets and personal data, message length.", "Refused before any agent sees the message."],
    ["Route", "Every hand-over between agents, workflow step, graph node and agent-as-tool call: a generated permit must exist, domains must be respected, order rules apply.", "A transfer the design never intended is refused."],
    ["Tool", "A generated placement exists, the decision point allows it, a short-lived permit is issued, the end-user role fits, argument rules hold, a human approves critical operations.", "Password reset waits for a signed approval."],
    ["Tool result", "Declared fields are masked; injection and secret patterns are denied or flagged (a flag taints the run).", "E-mail addresses are masked; later side effects need approval after a flag."],
    ["Model", "The model is offered only the functions the bundle lists for that agent; any other function call is refused.", "A hallucinated or injected tool call does nothing."],
    ["Output", "Personal data and secrets in text shown to the user, and the decision point's output placement.", "A reply containing an SSN is withheld."],
  ];
  const FLOW = [["User message", 0], ["Input check", 1], ["Entry agent", 0], ["Route check", 1], ["Another agent", 0], ["Tool check + approval + permit", 1], ["Tool runs", 0], ["Result check", 1], ["Output check", 1], ["User sees answer", 0]];
  const TERMS = [
    ["PEP", "Policy Enforcement Point: where a request is stopped and checked. The Backplane generates one for every interaction."],
    ["PDP", "Policy Decision Point: answers allow, deny or hold from the signed rules. Decisions are signed and bound to the exact request."],
    ["PSL", "The policy language the rules are written in. Rules carry a plain-language sentence that the Policies page shows."],
    ["Bundle", "The signed protection package made by 'zt-adk build': system model, policies, report. A changed application invalidates it."],
    ["Fingerprint", "A hash of the application's structure and tool code evidence. The runtime refuses a bundle that no longer matches the code."],
    ["Permit Lease", "A short-lived, request-bound permit issued after an allow decision. A different request cannot reuse it."],
    ["Approval", "A human decision signed with the approver's own key, bound to one exact request, single use and time limited."],
    ["Taint", "A run is marked riskier after flagged content; side effects then need approval."],
    ["Domain", "A group of agents (for example one office). Rules can stop agents crossing domains."],
    ["Enforce / Shadow", "Enforce blocks. Shadow only logs, except that critical operations stay blocked. Do not use shadow in production."],
    ["Playback model", "A scripted stand-in for the language model used for tests and keyless demos. Agents, tools and checks still run for real."],
    ["Expectation", "In the Test Lab you can say what should happen (blocked at the input boundary, rule X fires, answer must not contain Y). The run is then marked pass or fail."],
  ];
  v.append(h("h1", null, "How the Backplane works"),
    h("p", null, "The Backplane protects a multi-agent application written with Google ADK without changing its code. It studies the application, generates a signed set of rules (the bundle), and then checks every step while the application runs. Every decision is written to an audit log."),
    h("h2", null, "The six boundaries"),
    h("table", null, h("tr", null, h("th", null, "Boundary"), h("th", null, "What is checked"), h("th", null, "Example")), BOUNDARIES.map((b) => h("tr", null, h("td", null, h("b", null, b[0])), h("td", null, b[1]), h("td", null, b[2])))),
    h("h2", null, "Life of a request"),
    h("div", { class: "flow" }, FLOW.flatMap((f, i) => [h("div", { class: `box ${f[1] ? "gate" : ""}` }, f[0]), i < FLOW.length - 1 ? h("span", { class: "arrow" }, "→") : null])),
    h("p", { class: "muted" }, "Highlighted boxes are checks. Any check can stop the request; a stop is recorded and explained in the Trace viewer and on the Audit page."),
    h("h2", null, "How to test it in four steps"),
    h("ol", null, h("li", null, "Pick the application at the top right. Use Create keys and Build bundle once (Test Lab, Application box)."),
      h("li", null, "Load a preset (for example the prompt-injection phrase) or type your own message, role and optional expectations."),
      h("li", null, "Press Run. The Trace viewer shows the verdict, the answer and every boundary decision in plain language, and whether your expectations held."),
      h("li", null, "Save useful runs as tests, then run them again as a batch or campaign after any change to the application or the rules.")),
    h("h2", null, "Words you will meet"), h("dl", { class: "gloss" }, TERMS.flatMap((t) => [h("dt", null, t[0]), h("dd", null, t[1])])),
    h("h2", null, "Same things from a terminal"),
    h("table", null, h("tr", null, h("th", null, "Command"), h("th", null, "What this console does with it")),
      [["zt-adk keys init --approver alice --secondary bob", "Create keys"], ["zt-adk build", "Build bundle"], ["zt-adk check", "Check bundle"], ["zt-adk run --role employee \"...\"", "Run (Test Lab)"], ["zt-adk approvals list | approve ID --approver NAME", "Approvals page"], ["zt-adk audit verify", "Verify chain (Audit page)"]]
        .map((c) => h("tr", null, h("td", { class: "mono" }, c[0]), h("td", null, c[1])))));
}

// ------------------------------------------------------------------ System
const PALETTE = ["#cfe3f5", "#d9efd2", "#f8e3c4", "#e6d6f0", "#f5d3d3", "#d4eee9", "#ecebc4"];
async function system(v) {
  const [d, o] = await Promise.all([api("/api/bp/system"), api("/api/bp/overview")]);
  const card = (num, lbl) => h("div", { class: "card" }, h("div", { class: "num" }, num), h("div", { class: "lbl" }, lbl));
  v.append(h("h1", null, `System: ${d.app}`),
    h("div", { class: "cards" }, card(o.mode, "mode"), card(o.environment, "environment"), card(o.counts.agents, "agents"), card(o.counts.tools, "tools"), card(o.counts.edges, "routes"), card(o.counts.placements, "enforcement placements"), card(o.audit.ok ? "intact" : "BROKEN", `audit chain (${o.audit.records} records)`), card(o.pending_approvals, "pending approvals")),
    h("table", { class: "kv" }, h("tr", null, h("th", null, "Policy version"), h("td", { class: "mono" }, o.policy_version)), h("tr", null, h("th", null, "Fingerprint"), h("td", { class: "mono" }, o.fingerprint)),
      h("tr", null, h("th", null, "Bundle built"), h("td", null, fmtTime(o.created_at))), h("tr", null, h("th", null, "End-user roles"), h("td", null, (o.roles || []).join(", ") || "none declared"))));
  if (o.mode === "shadow") v.append(notice("Shadow mode: denied non-critical operations still run (they are only logged). Use enforce mode for protection.", "err"));
  const domains = [...new Set(d.agents.map((a) => a.domain || "-"))];
  const color = (dom) => PALETTE[domains.indexOf(dom || "-") % PALETTE.length];
  const legend = h("div", { class: "legend" }, domains.map((dm, i) => { const sw = h("i"); sw.style.background = PALETTE[i % PALETTE.length]; return h("span", null, sw, dm); }));
  v.append(h("h2", null, "Agents"), h("p", { class: "muted" }, `Colours show security domains. Click an agent for details.`), legend);
  const byName = Object.fromEntries(d.agents.map((a) => [a.name, a])), kids = {};
  d.agents.forEach((a) => { const p = a.parent && byName[a.parent] ? a.parent : "__root"; (kids[p] = kids[p] || []).push(a.name); });
  const W = 150, H = 44, GX = 16, GY = 54, pos = {}; let leaf = 0, maxDepth = 0; const seen = new Set();
  const place = (name, depth) => {
    if (seen.has(name)) return; seen.add(name); maxDepth = Math.max(maxDepth, depth);
    const ch = (kids[name] || []).filter((c) => !seen.has(c));
    if (!ch.length) { pos[name] = { x: leaf * (W + GX), y: depth * (H + GY) }; leaf++; return; }
    ch.forEach((c) => place(c, depth + 1));
    const xs = ch.filter((c) => pos[c]).map((c) => pos[c].x);
    pos[name] = { x: (Math.min(...xs) + Math.max(...xs)) / 2, y: depth * (H + GY) };
  };
  (kids.__root || []).forEach((r) => place(r, 0));
  const svg = sv("svg", { width: Math.max(leaf, 1) * (W + GX), height: (maxDepth + 1) * (H + GY), role: "group", "aria-label": "Agent hierarchy" });
  Object.values(byName).forEach((a) => { const p = pos[a.name], par = a.parent && pos[a.parent]; if (p && par) svg.append(sv("line", { x1: par.x + W / 2, y1: par.y + H, x2: p.x + W / 2, y2: p.y, stroke: "#8fa3b8", "stroke-width": 1.5 })); });
  const detail = h("div", { class: "notice" }, "Select an agent.");
  const showAgent = (a) => {
    const out = d.edges.filter((e) => e.caller === a.name), inn = d.edges.filter((e) => e.target === a.name);
    clear(detail);
    detail.append(h("b", null, a.name), ` (${a.kind}, domain ${a.domain || "-"})`, h("p", null, a.description || ""),
      h("div", null, "Tools: ", a.tools.length ? d.tools.filter((t) => t.agent === a.name).map((t) => h("span", { class: "chip" }, t.name + " ", critChip(t.criticality))) : "none"),
      h("div", { class: "small muted" }, `Routes out: ${out.map((e) => `${e.kind}→${e.target}`).join(", ") || "none"}`), h("div", { class: "small muted" }, `Routes in: ${inn.map((e) => `${e.caller} (${e.kind})`).join(", ") || "none"}`));
  };
  Object.values(byName).forEach((a) => {
    const p = pos[a.name]; if (!p) return;
    const g = sv("g", { class: "node", tabindex: "0", role: "button",  onkeydown: (e) => { if (e.key === "Enter") g.dispatchEvent(new MouseEvent("click")); }, onclick: () => { svg.querySelectorAll(".node").forEach((n) => n.classList.remove("sel")); g.classList.add("sel"); showAgent(a); } },
      sv("rect", { x: p.x, y: p.y, width: W, height: H, rx: 5, fill: color(a.domain), stroke: "#6d8197" }),
      sv("text", { x: p.x + W / 2, y: p.y + 19, "text-anchor": "middle", "font-size": 12, "font-weight": "bold" }, a.name.length > 20 ? a.name.slice(0, 19) + "…" : a.name),
      sv("text", { x: p.x + W / 2, y: p.y + 34, "text-anchor": "middle", "font-size": 10, fill: "#445" }, `${a.kind}  |  ${a.tools.length} tool${a.tools.length === 1 ? "" : "s"}`));
    svg.append(g);
  });
  v.append(h("div", { class: "svgwrap" }, svg), detail,
    h("h2", null, "Tools and how they were classified"),
    h("p", { class: "muted" }, "Classification comes from your profile first, then from analysis of the tool's code, then from its name; if nothing explains a tool it is treated as a high-criticality side effect. Critical operations need approval."),
    h("div", { class: "tablewrap" }, h("table", null, h("tr", null, ["Tool", "Kind", "Action", "Side effect", "Criticality", "Data class", "Approval", "Masked", "Why (evidence)"].map((t) => h("th", null, t))),
      d.tools.map((t) => h("tr", null, h("td", { class: "mono" }, t.key), h("td", null, t.kind), h("td", null, t.action || ""), h("td", null, String(!!t.side_effect)), h("td", null, critChip(t.criticality)), h("td", null, t.classification || ""),
        h("td", null, t.requires_approval ? (t.secondary_approval ? "dual" : "yes") : "no"), h("td", null, (t.mask_fields || []).join(", ")), h("td", { class: "small" }, (t.evidence || []).slice(0, 3).join(" | ")))))),
    h("h2", null, "Routes"), h("table", null, h("tr", null, ["Kind", "From", "To", "Workflow"].map((t) => h("th", null, t))), d.edges.map((e) => h("tr", null, h("td", null, e.kind), h("td", null, e.caller), h("td", null, e.target), h("td", null, e.workflow || "")))));
}

// ------------------------------------------------------------------ Policies
async function policies(v) {
  const d = await api("/api/bp/policies");
  const search = h("input", { type: "search", placeholder: "Filter rules...", "aria-label": "Filter rules" }), list = h("div");
  const total = d.files.reduce((n, f) => n + f.rules.length, 0);
  v.append(h("h1", null, "Policies"), h("p", null, `Policy version ${d.version}. ${total} rules in ${d.files.length} files. Every decision comes from this signed store; your own rules can only narrow what the generated permits allow.`), h("div", { class: "row" }, h("div", null, h("label", null, "Search"), search)), list);
  const draw = () => {
    clear(list); const q = search.value.trim().toLowerCase();
    for (const f of d.files) {
      const rules = f.rules.filter((r) => !q || `${r.id} ${r.nl} ${r.effect}`.toLowerCase().includes(q));
      if (!rules.length && q) continue;
      list.append(h("details", { open: !!q || !f.file.startsWith("10_access") },
        h("summary", null, h("b", null, f.file), `  (${rules.length} rules)  `, h("span", { class: "muted" }, f.layer)),
        h("table", null, h("tr", null, ["Rule", "In plain language", "Effect", "Applies to"].map((t) => h("th", null, t))), rules.map((r) => h("tr", null, h("td", { class: "mono" }, r.id), h("td", null, r.nl), h("td", null, h("span", { class: "chip" }, r.effect)), h("td", { class: "small" }, r.scope))))));
    }
  };
  search.addEventListener("input", draw); draw();
}

// ------------------------------------------------------------------ Audit / Approvals
async function audit(v) {
  const f = { outcome: "", boundary: "", q: "" };
  const sel = (opts, key) => { const s = h("select", { "aria-label": key }, opts.map(([val, lbl]) => h("option", { value: val }, lbl))); s.addEventListener("change", () => { f[key] = s.value; load(false); }); return s; };
  const q = h("input", { type: "search", placeholder: "Search records...", "aria-label": "Search" });
  q.addEventListener("input", () => { f.q = q.value; clearTimeout(q._t); q._t = setTimeout(() => load(false), 250); });
  const verifyOut = h("div"), table = h("div");
  v.append(h("h1", null, "Audit log"), h("p", null, "Every decision the Backplane made, newest first, with a plain-language reading. Click a row for the record."),
    h("div", { class: "row" }, h("div", null, h("label", null, "Outcome"), sel([["", "all"], ["denied", "denied"], ["held", "held"], ["flagged", "flagged"], ["allowed", "allowed"]], "outcome")),
      h("div", null, h("label", null, "Boundary"), sel([["", "all"], ["Input", "Input"], ["Route", "Route"], ["Tool", "Tool"], ["Tool result", "Tool result"], ["Output", "Output"], ["Model", "Model"], ["Approval", "Approval"], ["Workflow", "Workflow"]], "boundary")),
      h("div", null, h("label", null, "Search"), q), h("div", { class: "right" }, h("button", { class: "secondary", onclick: () => load(false) }, "Refresh"), h("button", { onclick: doVerify }, "Verify chain"))), verifyOut, table);
  async function doVerify() {
    const r = await api("/api/bp/audit/verify"); clear(verifyOut);
    verifyOut.append(notice(r.ok ? `Chain intact: ${r.records} records, head ${shortHash(r.head)}…  Note: the chain is unkeyed, so this detects accidental or naive edits only; it is not proof against a determined attacker.` : `Chain broken: ${r.error}`, r.ok ? "ok" : "err"));
  }
  // Pages are anchored to the newest record seen when the list was (re)loaded, so records written meanwhile cannot shift or repeat rows.
  let items = [], total = 0, truncated = false, newest = 0;
  async function load(more) {
    if (!more) { items = []; newest = 0; }
    const d = await api(`/api/bp/events?limit=${AUDIT_PAGE}&offset=${items.length}&max_seq=${newest}&outcome=${encodeURIComponent(f.outcome)}&boundary=${encodeURIComponent(f.boundary)}&q=${encodeURIComponent(f.q)}`);
    if (!more && d.items.length) newest = Number(d.items[0].seq) || 0;
    items = items.concat(d.items); total = d.total; truncated = d.truncated;
    draw();
  }
  function draw() {
    clear(table);
    if (truncated) table.append(notice(LOG_WINDOW_NOTE));
    table.append(h("div", { class: "muted" }, `${total} records${total > items.length ? ` (showing ${items.length})` : ""}`),
      h("div", { class: "tablewrap" }, h("table", null, h("tr", null, ["#", "Time", "Boundary", "Outcome", "From → To", "What happened"].map((t) => h("th", null, t))),
        items.flatMap((e) => {
          const detail = h("tr", { class: "hidden" }, h("td", { colspan: 6 }, h("pre", null, JSON.stringify(e.raw, null, 2))));
          const row = h("tr", { class: "clickable", onclick: () => detail.classList.toggle("hidden") }, h("td", { class: "mono" }, e.seq), h("td", null, fmtTime(e.ts)), h("td", null, e.boundary), h("td", null, h("span", { class: `tag out-${e.outcome}` }, e.outcome)),
            h("td", { class: "mono small" }, `${e.caller || ""} → ${e.target || ""}`), h("td", null, e.text, (e.rules || []).map((r) => h("div", { class: "small muted" }, `${r.id}${r.text ? " – " + r.text : ""}`))));
          return [row, detail];
        }))),
      total > items.length ? h("p", null, h("button", { class: "secondary", onclick: () => load(true) }, `Load more (${total - items.length} remaining)`)) : null);
  }
  await load(false);
}
async function approvals(v) {
  const list = h("div");
  v.append(h("h1", null, "Approvals"), h("p", null, "Critical operations wait here for a signed human decision. An approval is bound to the exact arguments shown, can be used once, and expires."), list);
  api("/api/bp/setup").then(setNames).catch(() => {});
  const load = async () => { const a = await api("/api/bp/approvals"); clear(list); list.append(a.length ? a.map((x) => approvalCard(x, load)) : notice("No approval requests yet. In the Test Lab, run the preset 'Critical operation is held without approval'.")); refreshBadge(); };
  await load(); timers.push(setInterval(() => load().catch(() => {}), 3000));
}

// ------------------------------------------------------------------ Dashboard
async function dashboard(v) {
  const st = S.status;
  const setup = await api("/api/bp/setup").catch(() => ({}));
  const ready = st.configured && setup.command;
  const presets = st.can_run ? await api("/api/bp/scenarios").catch(() => []) : [];
  const demo = h("button", { class: "accent", disabled: !presets.length, title: presets.length ? "" : "Presets exist for the helpdesk example. For another application, write tests in the Test Lab and save them.", onclick: () => { L.autorun = "presets"; location.hash = "#/lab"; } }, "Run the demo test suite");
  v.append(h("div", { class: "hero" }, h("h1", null, "Run, test and understand the Zero Trust Backplane"),
    h("p", null, "Send any message through a protected multi-agent application, see which boundary decided what in plain language, state what should happen, and re-run it all after every change."),
    h("a", { class: "btn accent", href: "#/lab" }, "Open the Test Lab"), demo, h("a", { class: "btn secondary", href: "#/learn" }, "How it works")));
  const step = (ok, label, hint) => h("li", null, h("span", { class: ok ? "ok" : "todo" }, ok ? "✓" : "!"), h("span", null, label, hint && !ok ? h("span", { class: "muted" }, `  ${hint}`) : null));
  const checklist = h("div", null, h("h2", null, "Setup"), h("ul", { class: "steps" },
    step(!!st.profile, st.profile ? `Application: ${st.profile}` : "Application selected", "start the console with --profile"),
    step(!!setup.command, "zt-adk command found", "install zt-adk in this Python environment"),
    step(!!setup.keys, "Keys created", "Test Lab → Create keys"), step(!!st.configured, "Protection bundle built", "Test Lab → Build bundle")));
  if (!ready) { v.append(h("div", { class: "pad-inner" }, checklist, h("p", null, h("a", { class: "btn", href: "#/lab" }, "Finish setup in the Test Lab")))); return; }
  const [stats, ov, runs] = await Promise.all([api("/api/bp/stats"), api("/api/bp/overview"), api("/api/bp/runs").catch(() => [])]);
  if (stats.truncated) v.append(notice(LOG_WINDOW_NOTE));
  const o = stats.by_outcome, card = (num, lbl) => h("div", { class: "card" }, h("div", { class: "num" }, num), h("div", { class: "lbl" }, lbl));
  v.append(h("div", { class: "cards" }, card(stats.runs, "runs recorded"), card(stats.decisions, "decisions made"), card(o.allowed || 0, "allowed"), card(o.denied || 0, "denied"), card(o.held || 0, "held for approval"), card(o.flagged || 0, "flagged"), card(ov.audit.ok ? "intact" : "BROKEN", "audit chain")));
  const ORDER = ["Input", "Route", "Tool", "Tool result", "Model", "Output", "Approval", "Workflow", "Identity"];
  const bounds = ORDER.filter((b) => stats.by_boundary[b]);
  const max = Math.max(1, ...bounds.map((b) => Object.values(stats.by_boundary[b]).reduce((a, c) => a + c, 0)));
  const chart = h("div", null, h("h2", null, "Decisions by boundary"),
    h("div", { class: "keyrow" }, [["allowed", "allowed"], ["flagged", "flagged"], ["held", "held"], ["denied", "denied"], ["info", "recorded"]].map(([k, l]) => { const sw = h("i"); sw.className = `seg-${k}`; return h("span", null, sw, l); })),
    bounds.length ? bounds.map((b) => {
      const c = stats.by_boundary[b], total = Object.values(c).reduce((a, n) => a + n, 0), stack = h("div", { class: "stack" });
      stack.style.width = `${Math.max(8, (total / max) * 100)}%`;
      ["allowed", "info", "flagged", "held", "denied"].forEach((k) => { if (c[k]) { const seg = h("i", { class: `seg seg-${k}`, title: `${k}: ${c[k]}` }); seg.style.width = `${(c[k] / total) * 100}%`; stack.append(seg); } });
      return h("div", { class: "chartrow" }, h("span", null, b), h("div", null, stack), h("span", { class: "muted" }, total));
    }) : h("p", { class: "muted" }, "No decisions yet. Run a test in the Test Lab."));
  const rules = h("div", null, h("h2", null, "Rules that stopped, held or flagged requests"),
    stats.top_rules.length ? h("table", null, h("tr", null, ["Rule", "Times", "In plain language"].map((t) => h("th", null, t))), stats.top_rules.map((r) => h("tr", null, h("td", { class: "mono" }, r.id), h("td", null, r.count), h("td", { class: "small" }, r.text || "")))) : h("p", { class: "muted" }, "Nothing has been stopped yet."));
  v.append(h("div", { class: "two" }, chart, rules));
  v.append(h("div", { class: "two" }, checklist, h("div", null, h("h2", null, "Protected application"),
    h("table", { class: "kv" }, h("tr", null, h("th", null, "Application"), h("td", null, ov.app)), h("tr", null, h("th", null, "Mode / environment"), h("td", null, `${ov.mode} / ${ov.environment}`)),
      h("tr", null, h("th", null, "Agents / tools / routes"), h("td", null, `${ov.counts.agents} / ${ov.counts.tools} / ${ov.counts.edges}`)), h("tr", null, h("th", null, "Policy version"), h("td", { class: "mono" }, ov.policy_version)),
      h("tr", null, h("th", null, "Pending approvals"), h("td", null, ov.pending_approvals))))));
  if (ov.mode === "shadow") v.append(notice("Shadow mode: denied non-critical operations still run (they are only logged). Use enforce mode for protection.", "err"));
  v.append(h("h2", null, "Recent test runs"), runs.length ? h("div", { class: "tablewrap" }, h("table", null, h("tr", null, ["When", "Test", "Conversation", "Outcome", "Result"].map((t) => h("th", null, t))),
    runs.slice(0, 8).map((r) => h("tr", { class: "clickable", onclick: () => { L.last = null; location.hash = "#/lab"; } }, h("td", { class: "small" }, fmtTime(r.ts)), h("td", null, r.name || ""), h("td", { class: "small" }, r.messages.join("  |  ")),
      h("td", null, h("span", { class: `tag out-${r.state === "blocked" ? "denied" : r.state === "held" ? "held" : r.state === "flagged" ? "flagged" : "allowed"}` }, r.state)), h("td", { class: r.passed === true ? "pass" : r.passed === false ? "fail" : "pending" }, r.passed === true ? "PASS" : r.passed === false ? "FAIL" : "-"))))) : h("p", { class: "muted" }, "No runs yet."));
}
