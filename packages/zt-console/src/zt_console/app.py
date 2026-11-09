"""The console's HTTP API and static single-page UI.

It is a thin surface over the real command line: runs, builds and checks start the same
``zt-adk`` commands a terminal user would type, and everything shown is read from the files the Backplane writes.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__
from .backplane import Backplane, BackplaneUnavailable
from .casestore import CaseError, CaseStore
from .config import Config
from .runlog import RunLog
from .runner import (RunRejected, cancel_current, decide_approval, load_scenarios, run_messages, run_setup,
                     setup_status)
from .security import GuardMiddleware

PKG = Path(__file__).resolve().parent
STATIC, SEED = PKG / "static", PKG / "seed"
PROFILE_HEADER = "x-zt-profile"


class RunBody(BaseModel):
    messages: list[str] | None = Field(default=None, max_length=10)
    message: str | None = Field(default=None, max_length=10_000)
    role: str = Field(default="", max_length=60)
    expect: dict[str, Any] | None = None
    name: str = Field(default="", max_length=120)


class DecisionBody(BaseModel):
    decision: str
    approver: str = Field(max_length=60)
    secondary: bool = False
    comment: str = Field(default="", max_length=500)


class SetupBody(BaseModel):
    """Optional names for 'Create keys'; every other setup action ignores them."""
    approver: str = Field(default="alice", max_length=40)
    secondary: str = Field(default="bob", max_length=40)


class Workspace:
    """The profiles the console may use. The UI can pick one per request but never names a path itself."""

    def __init__(self, cfgs: list[Config]) -> None:
        self.cfgs = cfgs
        self.bps = [Backplane(c) for c in cfgs]

    def describe(self) -> list[dict[str, Any]]:
        names = [str(c.profile) if c.profile else "(no profile)" for c in self.cfgs]
        try:
            base = os.path.commonpath([str(Path(n).parent) for n in names]) if len(names) > 1 and all(c.profile for c in self.cfgs) else ""
        except ValueError:                                  # profiles on different drives have no common folder
            base = ""
        out = []
        for i, c in enumerate(self.cfgs):
            label = os.path.relpath(names[i], base) if base else (c.profile.name if c.profile else names[i])
            out.append({"index": i, "label": label, "app": c.app, "built": c.configured,
                        "keys": setup_status(c)["keys"]})
        return out


class Ctx:
    """The application one request is about. The page sends its choice with every request, so two browser tabs
    can work on different applications at the same time."""

    def __init__(self, ws: Workspace, index: int) -> None:
        self.index, self.cfg, self.bp = index, ws.cfgs[index], ws.bps[index]


def _ignore_data_dir(path: Path) -> None:
    """Make the data folder ignore itself in git (the same trick caches use), so saved tests and run history
    created in a working copy of a repository are never committed by accident."""
    marker = path / ".gitignore"
    try:
        if not marker.exists():
            marker.write_text("# Created by zt-console: local run history and saved tests.\n*\n", encoding="utf-8")
    except OSError:
        pass                                                # read-only location: nothing to protect


def create_app(cfg: Config, profiles: list[Config] | None = None) -> FastAPI:
    ws = Workspace(profiles or [cfg])
    app = FastAPI(title="ZT Console", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(GuardMiddleware, allowed_hosts=cfg.allowed_hosts)
    cases = CaseStore(cfg.data_dir / "tests.json")
    runs = RunLog(cfg.data_dir / "runs")
    _ignore_data_dir(cfg.data_dir)

    def ctx(request: Request) -> Ctx:
        """The profile named by the page (0 when absent, malformed or out of range, e.g. after a restart)."""
        try:
            index = int(request.headers.get(PROFILE_HEADER, "0"))
        except ValueError:
            index = 0
        return Ctx(ws, index if 0 <= index < len(ws.cfgs) else 0)

    @app.exception_handler(BackplaneUnavailable)
    async def _unavailable(_: Request, exc: BackplaneUnavailable) -> JSONResponse:
        return JSONResponse({"error": str(exc), "unavailable": True}, status_code=409)

    @app.exception_handler(CaseError)
    async def _case_error(_: Request, exc: CaseError) -> JSONResponse:
        return JSONResponse({"error": str(exc)}, status_code=400)

    @app.exception_handler(RunRejected)
    async def _rejected(_: Request, exc: RunRejected) -> JSONResponse:
        return JSONResponse({"error": str(exc)}, status_code=400)

    def app_name(c: Ctx) -> str:
        """The name new tests and runs are filed under: the profile's app string, which does not change when the
        bundle is built or deleted (the bundle's own name is used only if the profile has none)."""
        return c.cfg.app or c.bp.bundle_app_name()

    def app_names(c: Ctx) -> tuple[str, ...]:
        """Every name the selected application is known by. Before the first build only the profile's app string
        exists and the built bundle then names the app differently, so tests saved earlier must match both."""
        return tuple(dict.fromkeys(n for n in (c.bp.bundle_app_name(), c.cfg.app) if n))

    # ------------------------------------------------------------------ status, setup
    @app.get("/api/status")
    def status(c: Ctx = Depends(ctx)) -> dict[str, Any]:
        k = c.cfg
        return {"version": __version__, "configured": k.configured, "profile": k.profile.name if k.profile else None,
                "app": k.app, "dev_approve": k.dev_approve,
                "can_run": bool(k.zt_adk) and k.configured, "profiles": ws.describe(), "index": c.index}

    @app.get("/api/bp/setup")
    def setup(c: Ctx = Depends(ctx)) -> dict[str, Any]:
        return setup_status(c.cfg)

    @app.post("/api/bp/setup/{action}")
    def setup_action(action: str, body: SetupBody | None = None, c: Ctx = Depends(ctx)) -> dict[str, Any]:
        body = body or SetupBody()
        return run_setup(c.cfg, action, approver=body.approver, secondary=body.secondary)

    @app.post("/api/bp/cancel")
    def cancel() -> dict[str, bool]:
        """Stop the command that is running (a run or a setup action). ``cancelled`` is false when none is."""
        return {"cancelled": cancel_current()}

    # ------------------------------------------------------------------ backplane (read-only views)
    @app.get("/api/bp/overview")
    def overview(c: Ctx = Depends(ctx)) -> dict[str, Any]:
        return c.bp.overview()

    @app.get("/api/bp/system")
    def system(c: Ctx = Depends(ctx)) -> dict[str, Any]:
        return c.bp.system()

    @app.get("/api/bp/policies")
    def policies(c: Ctx = Depends(ctx)) -> dict[str, Any]:
        return c.bp.policies()

    @app.get("/api/bp/events")
    def events(limit: int = 200, offset: int = 0, outcome: str = "", boundary: str = "", max_seq: int = 0,
               q: str = Query("", max_length=100), c: Ctx = Depends(ctx)) -> dict[str, Any]:
        return c.bp.events(limit=limit, offset=offset, outcome=outcome, boundary=boundary, q=q, max_seq=max_seq)

    @app.get("/api/bp/stats")
    def stats(c: Ctx = Depends(ctx)) -> dict[str, Any]:
        return c.bp.stats()

    @app.get("/api/bp/audit/verify")
    def verify(c: Ctx = Depends(ctx)) -> dict[str, Any]:
        return c.bp.verify()

    @app.get("/api/bp/approvals")
    def approvals(c: Ctx = Depends(ctx)) -> list[dict[str, Any]]:
        return c.bp.approvals()

    @app.post("/api/bp/approvals/{approval_id}/decision")
    def decision(approval_id: str, body: DecisionBody, c: Ctx = Depends(ctx)) -> dict[str, Any]:
        if body.decision not in ("approve", "deny"):
            raise RunRejected("decision must be approve or deny")
        return decide_approval(c.cfg, c.bp, approval_id, body.decision == "approve", body.approver, body.secondary,
                               body.comment)

    # ------------------------------------------------------------------ test lab
    @app.get("/api/bp/scenarios")
    def scenarios(c: Ctx = Depends(ctx)) -> list[dict[str, Any]]:
        return load_scenarios(SEED, app_names(c))

    @app.get("/api/bp/cases")
    def list_cases(c: Ctx = Depends(ctx)) -> list[dict[str, Any]]:
        return cases.list(app_names(c))

    @app.post("/api/bp/cases")
    def save_case(body: dict[str, Any], c: Ctx = Depends(ctx)) -> dict[str, Any]:
        return cases.save(body, app_name(c))

    @app.delete("/api/bp/cases/{case_id}")
    def delete_case(case_id: str) -> dict[str, Any]:
        if not cases.delete(case_id):
            raise HTTPException(404, "no such test")
        return {"deleted": case_id}

    @app.post("/api/bp/run")
    def run(body: RunBody, c: Ctx = Depends(ctx)) -> dict[str, Any]:
        msgs = body.messages if body.messages else ([body.message] if body.message is not None else [])
        result = run_messages(c.cfg, c.bp, msgs, body.role, body.expect)
        result["run_id"] = runs.add(app_name(c), body.name, result)
        return result

    @app.get("/api/bp/runs")
    def list_runs(c: Ctx = Depends(ctx)) -> list[dict[str, Any]]:
        return runs.list(app_names(c))

    @app.get("/api/bp/runs/{run_id}")
    def get_run(run_id: str) -> dict[str, Any]:
        found = runs.get(run_id)
        if found is None:
            raise HTTPException(404, "no such run")
        return found

    # ------------------------------------------------------------------ UI
    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html", media_type="text/html")

    app.mount("/assets", StaticFiles(directory=STATIC), name="assets")
    return app
