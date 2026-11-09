# zt-console

A browser UI for **setting up, running and testing** the Zero Trust Backplane. It is a thin surface over the real
command line, with a **test editor** on the left and a **trace viewer** on the right. It holds no protection logic:
every run, build and check starts the same `zt-adk` command you would type in a terminal, and everything shown is
read from the files the Backplane writes. Installing it changes nothing in the other packages.

* **[User guide](docs/ZT_CONSOLE_GUI_USER_GUIDE.md)**: [what the GUI supports](docs/ZT_CONSOLE_GUI_USER_GUIDE.md#what-the-gui-supports),
  configuration, a first run, every page, recipes, limitations and troubleshooting.
* **[Where the GUI attaches](docs/ZT_CONSOLE_GUI_PLACEMENT.md)**: design note on how the GUI sits on top of the Backplane.

## Start

```bash
# from the repository root, in the environment where the Backplane is installed (Python 3.11 or newer)
python -m pip install -e packages/zt-console            # adds fastapi, uvicorn, PyYAML

# Work on a copy: Create keys / Build bundle write a .zt folder next to the profile.
cp -R examples/helpdesk_mas /tmp/helpdesk_mas
zt-console --profile /tmp/helpdesk_mas/zt_adk.playback.yaml
# open http://127.0.0.1:8766
```

In the browser: **Test Lab → Create keys → Build bundle**, then pick a preset and press **Run**.
The playback profile uses a scripted stand-in for the language model, so no API key is needed.

* `zt-adk` must be installed in the same environment (it is what runs the messages).
* `--profile` can be repeated, or use `--profiles-dir DIR` to pick the application in the browser (each browser tab
  keeps its own choice). With neither, the console looks for `zt_adk*.yaml` up to three folders below the current directory.
* `--dev-approve` (development machines only) lets you approve held operations from the page with local approver keys.
* `--data-dir DIR` is where saved tests and run history live (default `.zt-console`; it ignores itself in git).
* `--port N`, `--host H`, `--zt-adk PATH` complete the options. `zt-console --help` lists them.

## What you can do

| Page | Purpose |
|---|---|
| **Dashboard** | Setup checklist for a first run, decisions by boundary, the rules that stopped or held requests, recent runs, and one button to run the demo suite. |
| **Test Lab** | Type any message (several turns allowed), choose the end-user role, optionally state what should happen (outcome, boundary, rule that must fire, text the answer must or must not contain), and **Run**. Save runs as tests, run a **batch** (one message per line), or run saved tests and presets as a **campaign**; export results as JSON, CSV or a Markdown report. A run in progress can be **stopped**; the draft and results survive a page reload. The trace viewer shows the verdict, the answer and every boundary decision in plain language, with the rule sentences behind them. Earlier runs can be reloaded. |
| **Learn** | How the Backplane works: boundaries, life of a request, glossary, the equivalent terminal commands. |
| **System** | The loaded application: agents by security domain, tools and how each was classified (and why), routes, bundle facts. |
| **Policies** | Every rule in the signed policy store with its plain-language sentence, searchable. |
| **Audit** | Every recorded decision with a plain-language reading, filters, and chain verification. |
| **Approvals** | Held critical operations with the exact arguments being approved. |

## Safety of the console itself

It displays text that attackers can influence (messages, tool arguments, audit records), so:

* it binds to `127.0.0.1` and answers only for configured hosts (blocks DNS rebinding);
* every state-changing request needs a custom header (blocks cross-site posts);
* a strict content security policy is sent, and the UI never uses `innerHTML` or inline styles: all values are added as text;
* exported CSV cells that start with `=`, `+`, `-` or `@` are prefixed so a spreadsheet does not run them as formulas;
* messages are passed to `zt-adk` as an argument list after `--` (no shell, so a message cannot become an option), with a
  size limit, a role allow-list, one operation at a time and a time limit;
* the UI can only choose among the profiles the server was started with; it never supplies a path;
* it never reads or shows key material. Approving from the page is off unless `--dev-approve` is given.

It has **no user authentication** and is meant for a single local user.

## Tests

```bash
python -m pip install -e "packages/zt-console[test]"
python -m pytest packages/zt-console/tests              # API and unit tests; no Docker, ADK or API key needed
```

The unit tests use a small synthetic bundle and a stand-in for `zt-adk`. One test compares the console's audit
verification with `zt_adk.audit.verify_chain` when `zt-adk` is installed.

A browser end-to-end test and an accessibility audit (axe-core at desktop, tablet and phone widths) drive the real
`zt-adk` from a fresh application with no keys and no bundle. They are not part of the unit tests because they need
Chrome and Node; the commands are in [section 9 of the user guide](docs/ZT_CONSOLE_GUI_USER_GUIDE.md#9-verification).

## Limits

The full list, with the reason for each, is in [section 7 of the user guide](docs/ZT_CONSOLE_GUI_USER_GUIDE.md#7-limitations). In short:

* It drives the **in-process** protection (`zt-adk run`). The distributed Docker runtime is not driven from the page.
* No user authentication; local single-user use only.
* The audit-chain check is unkeyed: it detects accidental edits, not a determined attacker.
* Verified with the scripted (playback) model; a live model changes answers and timing, not the checks.
