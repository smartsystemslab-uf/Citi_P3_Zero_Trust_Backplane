"""Host-side orchestration of the distributed runtime's Docker deployment.

Everything here acts ONLY on compose project `citi_p3_ztbp` (containers ztbp-*, volumes
citi_p3_ztbp_*). Nothing touches other projects, global Docker settings or the source
repositories.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]               # distributed_runtime/
BACKPLANE = ROOT.parent
sys.path.insert(0, str(ROOT))
from zt_distributed import catalog  # noqa: E402

COMPOSE_FILE = ROOT / "deploy" / "compose.yaml"
PUBLIC = ROOT / "runtime" / "public"
RESULTS = ROOT / "results"
LIVE = RESULTS / "live"
STAGED_MAS = ROOT / "runtime" / "build" / "Citi_P3"
SPIRE_SOCK = "/tmp/spire-server/private/api.sock"
P = catalog.CONTAINER_PREFIX
AGENT_SERVICES = [w.name for w in catalog.AGENTS.values()]
IMAGES = {"runtime": "citi-ztbp/runtime:dev", "backend": "citi-ztbp/backend:dev", "spire": "citi-ztbp/spire:1.15.3"}

# project-local docker client config (no stored registry credentials); ~/.docker is never modified
DOCKER_ENV = dict(os.environ)
DOCKER_ENV.setdefault("DOCKER_CONFIG", str(ROOT / "runtime" / "docker-config"))
DOCKER_ENV.setdefault("DOCKER_BUILDKIT", "1")
if os.name == "nt":
    DOCKER_ENV.setdefault("DOCKER_HOST", "npipe:////./pipe/dockerDesktopLinuxEngine")
(ROOT / "runtime" / "docker-config").mkdir(parents=True, exist_ok=True)
if not (ROOT / "runtime" / "docker-config" / "config.json").exists():
    (ROOT / "runtime" / "docker-config" / "config.json").write_text("{}")


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def run(cmd: list[str], *, env: dict[str, str] | None = None, check: bool = True, capture: bool = True,
        timeout: float | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess:
    e = dict(DOCKER_ENV)
    if env:
        e.update(env)
    p = subprocess.run(cmd, env=e, capture_output=capture, text=True, timeout=timeout, cwd=cwd,
                       encoding="utf-8", errors="replace")
    if check and p.returncode != 0:
        raise RuntimeError(f"command failed ({p.returncode}): {' '.join(cmd)}\n{(p.stdout or '')[-3000:]}\n"
                           f"{(p.stderr or '')[-3000:]}")
    return p


def compose(*args: str, env: dict[str, str] | None = None, check: bool = True, timeout: float | None = 900) -> str:
    return run(["docker", "compose", "-f", str(COMPOSE_FILE), *args], env=env, check=check, timeout=timeout).stdout


def dexec(container: str, *args: str, user: str | None = None, check: bool = True, timeout: float = 180) -> str:
    cmd = ["docker", "exec"]
    if user:
        cmd += ["-u", user]
    return run(cmd + [f"{P}{container}", *args], check=check, timeout=timeout).stdout


def http_local(container: str, path: str, timeout: float = 5.0, method: str = "GET") -> dict[str, Any]:
    code = ("import sys,urllib.request as u;r=u.Request('http://127.0.0.1:%d'+sys.argv[1],"
            "data=(b'' if sys.argv[2]=='POST' else None),method=sys.argv[2]);"
            "sys.stdout.write(u.urlopen(r,timeout=%s).read().decode())" % (catalog.OPS_PORT, timeout))
    return json.loads(dexec(container, "python", "-c", code, path, method, timeout=timeout + 30))


def wait_health(container: str, timeout: float = 300) -> dict[str, Any]:
    deadline = time.time() + timeout
    last: Exception | None = None
    while time.time() < deadline:
        try:
            h = http_local(container, "/health")
            if h.get("status") == "ok":
                return h
        except Exception as exc:  # container still starting
            last = exc
        time.sleep(1.0)
    logs = run(["docker", "logs", "--tail", "40", f"{P}{container}"], check=False)
    raise RuntimeError(f"{container} not healthy after {timeout}s: {last}\n{logs.stdout[-2000:]}{logs.stderr[-2000:]}")


def running_containers() -> list[str]:
    out = run(["docker", "ps", "--filter", f"label=com.docker.compose.project={catalog.COMPOSE_PROJECT}",
               "--format", "{{.Names}}"]).stdout
    return sorted(x.strip() for x in out.splitlines() if x.strip())


# ---------------------------------------------------------------------------
# build / prepare
# ---------------------------------------------------------------------------
def build(stage: bool = True) -> dict[str, str]:
    if stage or not STAGED_MAS.exists():
        from scripts.stage_mas import stage as stage_mas
        log("staging MAS build input (read-only copy of the MAS repository)")
        stage_mas(Path(os.environ.get("CITI_MAS_SRC", r"D:\Lab\Citi_P3")), STAGED_MAS)
    ctx = ["--build-context", f"citi_mas={STAGED_MAS}"]
    steps = [
        (["-f", str(ROOT / "deploy/docker/spire.Dockerfile"), "-t", IMAGES["spire"], str(ROOT)]),
        (["-f", str(ROOT / "deploy/docker/backend.Dockerfile"), *ctx, "-t", IMAGES["backend"], str(BACKPLANE)]),
        (["-f", str(ROOT / "deploy/docker/runtime.Dockerfile"), *ctx, "-t", IMAGES["runtime"], str(BACKPLANE)]),
    ]
    for args in steps:
        log("docker build " + " ".join(a for a in args if not a.startswith(("D:", "/", "C:"))))
        run(["docker", "build", "-q", *args], timeout=3600)
    return image_digests()


def gen_compose() -> None:
    run([sys.executable, str(ROOT / "deploy" / "gen_compose.py")])


def prepare() -> dict[str, Any]:
    gen_compose()
    (PUBLIC / "spire").mkdir(parents=True, exist_ok=True)
    (PUBLIC / "spire" / "bootstrap_bundle.pem").touch()
    LIVE.mkdir(parents=True, exist_ok=True)
    out = compose("run", "--rm", "ops", "python", "-m", "zt_distributed.prepare", timeout=1800)
    golden = compose("run", "--rm", "ops-backend", "python", "/opt/citi/backend_tools/make_golden.py",
                     "--out", "/golden/backend.db", timeout=1800)
    return {"prepare": json.loads(out.strip().splitlines()[-1]), "backend_golden": golden.strip().splitlines()[-1:]}


# ---------------------------------------------------------------------------
# SPIRE
# ---------------------------------------------------------------------------
def spire_up(svid_ttl: int = 0) -> dict[str, Any]:
    t0 = time.time()
    compose("up", "-d", "spire-server")
    deadline = time.time() + 90
    while True:
        p = run(["docker", "exec", f"{P}spire-server", "spire-server", "healthcheck", "-socketPath", SPIRE_SOCK],
                check=False)
        if p.returncode == 0:
            break
        if time.time() > deadline:
            raise RuntimeError("spire-server not healthy: " + p.stderr)
        time.sleep(1)
    bundle = run(["docker", "exec", f"{P}spire-server", "spire-server", "bundle", "show",
                  "-socketPath", SPIRE_SOCK]).stdout
    (PUBLIC / "spire" / "bootstrap_bundle.pem").write_text(bundle)
    reg = json.loads(run(["docker", "exec", f"{P}spire-server", "python3", "/opt/register.py",
                          "--x509-ttl", str(svid_ttl)]).stdout)
    compose("up", "-d", "spire-agent")
    deadline = time.time() + 90
    while True:
        p = run(["docker", "exec", f"{P}spire-agent", "spire-agent", "healthcheck", "-socketPath",
                 "/run/spire/sockets/agent.sock"], check=False)
        if p.returncode == 0:
            break
        if time.time() > deadline:
            raise RuntimeError("spire-agent not healthy: " + p.stderr)
        time.sleep(1)
    return {"spire_ready_s": round(time.time() - t0, 3),
            "registration": {k: v for k, v in reg.items() if k != "entries"}, "entries": reg["entries"]}


# ---------------------------------------------------------------------------
# data reset / verification
# ---------------------------------------------------------------------------
RESET_SCRIPT = (
    "set -e; cp /golden/adk_banking.db /var/lib/bankadk/banking.db; rm -f /var/lib/bankadk/banking.db-journal; "
    "cp /golden/backend.db /var/lib/bank/citi_banking.db; rm -f /var/lib/bank/citi_banking.db-journal; "
    "mkdir -p /var/lib/zt-gateway/output; "
    "rm -f /var/lib/zt-gateway/output/native_mas_audit.jsonl /var/lib/zt-gateway/output/task4_decision_log.jsonl "
    "/var/lib/zt-gateway/output/task4_policy_versions.json /var/lib/zt-gateway/output/psl_audit.jsonl; "
    "chown -R 20001:20001 /var/lib/bankadk /var/lib/zt-gateway; chown -R 20010:20010 /var/lib/bank; "
    "chown -R 20002:20002 /var/lib/agent-issuer"
)


def reset_data(*, issuer_state: bool = False) -> None:
    script = RESET_SCRIPT
    if issuer_state:
        script = "rm -rf /var/lib/agent-issuer/state.json /var/lib/agent-issuer/admin; " + script
    compose("run", "--rm", "ops", "sh", "-c", script)


def verify_state(archive_dir: Path | None = None) -> dict[str, Any]:
    args = ["run", "--rm", "ops", "python", "-m", "zt_distributed.verify_state"]
    if archive_dir is not None:
        args += ["--archive", "/results/" + archive_dir.relative_to(RESULTS).as_posix()]
    out = compose(*args)
    return json.loads(out.strip().splitlines()[-1])


# ---------------------------------------------------------------------------
# start / restart / stop
# ---------------------------------------------------------------------------
def stack_env(*, conn_mode: str = "reuse", session_tickets: str = "on", agent_cert_ttl: int = 86400,
              renew_fraction: float = 0.5) -> dict[str, str]:
    return {"CONN_MODE": conn_mode, "TLS_SESSION_TICKETS": session_tickets,
            "AGENT_CERT_TTL_SECONDS": str(agent_cert_ttl), "AGENT_RENEW_FRACTION": str(renew_fraction)}


def _wait_issuer(timeout: float = 90) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        p = run(["docker", "exec", f"{P}agent-issuer", "python", "-c",
                 "import os,sys;sys.exit(0 if os.path.exists('/var/lib/agent-issuer/admin/admin.sock') else 1)"],
                check=False)
        if p.returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError("agent-issuer did not become ready")


def start(*, agents: Iterable[str] | None = None, svid_ttl: int = 0, **env_kw: Any) -> dict[str, Any]:
    agents = list(agents or AGENT_SERVICES)
    env = stack_env(**env_kw)
    info: dict[str, Any] = {"agents": agents, "env": env, "svid_ttl": svid_ttl}
    t0 = time.time()
    compose("stop", "ingress-client", "zt-gateway", "agent-issuer", *AGENT_SERVICES, check=False)
    info["spire"] = spire_up(svid_ttl=svid_ttl)
    reset_data(issuer_state=True)
    ti = time.time()
    compose("up", "-d", "--force-recreate", "agent-issuer", env=env)
    _wait_issuer()
    info["issuer_ready_s"] = round(time.time() - ti, 3)
    compose("up", "-d", "--force-recreate", "bank-backend", "zt-gateway", env=env)
    info["gateway_health"] = wait_health("zt-gateway")
    ta = time.time()
    compose("up", "-d", "--force-recreate", *agents, "ingress-client", env=env)
    info["agent_health"] = {a: wait_health(a) for a in agents}
    info["agents_ready_wall_s"] = round(time.time() - ta, 3)
    info["start_total_s"] = round(time.time() - t0, 3)
    info["env_for_runs"] = env
    return info


def mcp_reconnect(agents: Iterable[str], reason: str = "operator") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for a in agents:
        try:
            out[a] = http_local(a, f"/mcp/reconnect?reason={reason}", timeout=60, method="POST")
        except Exception as exc:
            out[a] = {"status": "error", "error": str(exc)[-300:]}
    return out


def restart_gateway(env: dict[str, str], agents: Iterable[str] | None = None) -> dict[str, Any]:
    """Fresh PDP/PEP/permit/monitor state and restored data; every agent re-initializes its
    MCP session (the restarted gateway has none)."""
    compose("stop", "zt-gateway", "bank-backend", check=False)
    reset_data()
    compose("up", "-d", "--force-recreate", "bank-backend", "zt-gateway", env=env)
    health = wait_health("zt-gateway")
    rc = mcp_reconnect(list(agents or AGENT_SERVICES), "gateway_restart")
    bad = {a: v for a, v in rc.items() if v.get("status") != "ok"}
    if bad:
        raise RuntimeError(f"MCP reconnect failed after gateway restart: {json.dumps(bad)[:600]}")
    return health


def issuer_admin(action: str, agent_id: str) -> dict[str, Any]:
    return json.loads(dexec("agent-issuer", "python", "-m", "zt_identity.agent_identity.admin", action, agent_id))


def ingress(*args: str, timeout: float = 600) -> dict[str, Any]:
    out = dexec("ingress-client", "python", "-m", "zt_distributed.ingress_client", *args, timeout=timeout)
    return json.loads([ln for ln in out.strip().splitlines() if ln.startswith("{")][-1])


def stop_all(purge: bool = False) -> None:
    compose("--profile", "ops", "down", *(["-v"] if purge else []), check=False, timeout=300)


def rotate_live(dest: Path, wait_s: float = 1.6) -> list[str]:
    """Move live span/event logs of the finished run into the run directory."""
    time.sleep(wait_s)          # let the 1 s buffered writers flush
    dest.mkdir(parents=True, exist_ok=True)
    moved = []
    for f in sorted(LIVE.glob("*.jsonl")):
        try:
            shutil.move(str(f), str(dest / f.name))
            moved.append(f.name)
        except OSError:
            pass
    return moved


def image_digests() -> dict[str, str]:
    return {img: run(["docker", "image", "inspect", img, "--format", "{{.Id}}"], check=False).stdout.strip()
            for img in IMAGES.values()}
