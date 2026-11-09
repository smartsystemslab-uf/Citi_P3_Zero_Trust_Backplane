/* Accessibility and layout audit of every page of the ZT Console, at desktop, tablet and phone widths.

   For each page it runs axe-core (WCAG 2.1 A and AA plus best practices), checks for horizontal overflow, and records any
   JavaScript error or failed request. Exit code 0 only when there is nothing serious to report.

   BASE=http://127.0.0.1:8790 NODE_PATH=<node_modules with puppeteer-core@22 and axe-core> \
   node tests/e2e/a11y_audit.cjs */
const puppeteer = require("puppeteer-core");
const fs = require("fs");
const axeSource = fs.readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");
const BASE = process.env.BASE || "http://127.0.0.1:8766";
const CHROME = process.env.CHROME || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const WIDTHS = [[1440, 900, "desktop"], [820, 1000, "tablet"], [390, 800, "phone"]];
const PAGES = [[BASE, "dashboard"], [BASE, "lab"], [BASE, "learn"], [BASE, "system"], [BASE, "policies"], [BASE, "audit"], [BASE, "approvals"]];

(async () => {
  const browser = await puppeteer.launch({ executablePath: CHROME, headless: "new", args: ["--no-sandbox"] });
  const problems = [], rows = [];
  for (const [w, h, label] of WIDTHS) {
    const page = await browser.newPage();
    await page.setViewport({ width: w, height: h });
    const errs = [];
    page.on("pageerror", (e) => errs.push(`pageerror: ${e.message}`));
    page.on("console", (m) => { if (m.type() === "error") errs.push(`console.error: ${m.text()}`); });
    page.on("response", (r) => { if (r.status() >= 400 && r.status() !== 409) errs.push(`HTTP ${r.status()} ${r.url()}`); });
    for (const [base, path] of PAGES) {
      errs.length = 0;
      await page.setBypassCSP(true);                         // lets the audit inject axe; the page's own CSP is checked elsewhere
      await page.goto(`${base}/#/${path}`, { waitUntil: "networkidle0" });
      await page.reload({ waitUntil: "networkidle0" });
      await new Promise((r) => setTimeout(r, 600));
      await page.evaluate(axeSource);
      const result = await page.evaluate(async () => {
        const r = await axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"] } });
        return r.violations.map((v) => ({ id: v.id, impact: v.impact, help: v.help, nodes: v.nodes.length, sample: v.nodes[0].target.join(" ").slice(0, 90) }));
      });
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      const text = await page.evaluate(() => document.body.innerText);
      const bad = [];
      if (overflow > 2) {
        const wide = await page.evaluate(() => [...document.querySelectorAll("body *")].filter((e) => e.getBoundingClientRect().right > window.innerWidth + 2 && !e.closest(".tablewrap, .svgwrap, pre"))
          .slice(0, 4).map((e) => `${e.tagName.toLowerCase()}${e.className && typeof e.className === "string" ? "." + e.className.split(" ")[0] : ""} (${Math.round(e.getBoundingClientRect().right)}px)`));
        bad.push(`horizontal overflow ${overflow}px: ${wide.join(", ")}`);
      }
      if (/\[object |undefined|NaN/.test(text)) bad.push("page shows [object ...], undefined or NaN");
      for (const v of result) if (["serious", "critical", "moderate"].includes(v.impact)) bad.push(`axe ${v.impact}: ${v.id} (${v.nodes}) ${v.help} @ ${v.sample}`);
      for (const e of errs) bad.push(e);
      rows.push({ width: label, page: path, violations: result.length, problems: bad.length });
      for (const b of bad) problems.push(`[${label}] ${path}: ${b}`);
    }
    await page.close();
  }
  await browser.close();
  console.log(`${rows.length} page views checked (${PAGES.length} pages x ${WIDTHS.length} widths)`);
  if (problems.length) { console.log("PROBLEMS:"); [...new Set(problems)].forEach((p) => console.log(" - " + p)); process.exit(1); }
  console.log("No accessibility violations (serious, critical or moderate), no overflow, no errors.");
})().catch((e) => { console.error("audit crashed:", e); process.exit(2); });
