"""Host-side orchestration of the distributed runtime for ONE protected ADK application.

Everything here acts only on the compose project named in the application's profile
(``distributed.compose_project``, default ``citi_p3_ztbp``; containers ``<prefix>*``). Nothing touches
other projects, global Docker settings or the application's source tree (it is copied).

Layout (packages/zt-distributed/runtime/, not versioned):
  project.json          the application (profile path) the commands act on
  build/app/            staged copy of the application;  build/runtime.Dockerfile (generated)
  deployment.json       deployment descriptor (from `describe` inside the built image)
  compose.yaml          generated compose file
  spire/                SPIRE server/agent configuration for the trust domain
  public/               public material written by `prepare` (bundle, SPIRE entries, CA certs, registry)
  approver-keys/        approver private keys (host only; never mounted into a runtime container)
  state/gateway/        gateway audit, PDP decision log, PSL audit (bind mount)
  state/approvals/      approval requests and signed decisions (bind mount)
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable

from . import deployment as D

ROOT = Path(__file__).resolve().parents[2]               # packages/zt-distributed/ (deploy templates, state)
BACKPLANE = ROOT.parents[1]                              # repository root: the image build context

RUNTIME = ROOT / "runtime"
BUILD = RUNTIME / "build"
PUBLIC = RUNTIME / "public"
STATE = RUNTIME / "state"
APPROVERS = RUNTIME / "approver-keys"
DEPLOYMENT = RUNTIME / "deployment.json"
COMPOSE_FILE = RUNTIME / "compose.yaml"
PROJECT = RUNTIME / "project.json"
RESULTS = ROOT / "results"
LIVE = RESULTS / "live"
SPIRE_IMAGE = "zt-adk/spire:1.15.3"
SPIRE_SOCK = "/tmp/spire-server/private/api.sock"
PYTHON_IMAGE_DEFAULT = "python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e"
NET = "ztbp"
LIMITS = {"spire-server": ("1.0", "512m"), "spire-agent": ("1.0", "512m"), "zt-gateway": ("2.0", "2g"),
          "agent-issuer": ("1.0", "512m"), "ingress-client": ("1.0", "512m"), "agent": ("1.0", "1g")}

DOCKER_ENV = dict(os.environ)
DOCKER_ENV.setdefault("DOCKER_CONFIG", str(RUNTIME / "docker-config"))
DOCKER_ENV.setdefault("DOCKER_BUILDKIT", "1")
if os.name == "nt":
    DOCKER_ENV.setdefault("DOCKER_HOST", "npipe:////./pipe/dockerDesktopLinuxEngine")
(RUNTIME / "docker-config").mkdir(parents=True, exist_ok=True)
if not (RUNTIME / "docker-config" / "config.json").exists():
    (RUNTIME / "docker-config" / "config.json").write_text("{}")


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


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


def docker_build(args: list[str], context: Path) -> None:
    """``docker build`` that, on failure, reports the output of the step that failed (e.g. pip's
    resolution error) instead of only BuildKit's summary."""
    p = run(["docker", "build", "--progress=plain", *args, str(context)], check=False, timeout=3600)
    if p.returncode == 0:
        return
    out = (p.stderr or "") + (p.stdout or "")
    failed = re.findall(r"^#(\d+) ERROR", out, flags=re.M)
    lines = [ln for ln in out.splitlines() if failed and ln.startswith(f"#{failed[-1]} ")]
    detail = "\n".join(lines[-60:]) if lines else out[-6000:]
    raise RuntimeError(f"docker build failed ({p.returncode}): {' '.join(args)}\n{detail}")


# ---------------------------------------------------------------------------- project
def set_project(profile_path: Path) -> dict[str, Any]:
    profile_path = Path(profile_path).resolve()
    if profile_path.is_dir():
        profile_path = profile_path / "zt_adk.yaml"
    if not profile_path.exists():
        raise FileNotFoundError(f"no zt_adk.yaml at {profile_path}")
    RUNTIME.mkdir(parents=True, exist_ok=True)
    PROJECT.write_text(json.dumps({"profile": str(profile_path)}, indent=1))
    return {"profile": str(profile_path)}


def profile() -> Any:
    from zt_adk.profile import load_profile

    if not PROJECT.exists():
        raise RuntimeError("no project selected: run 'zt-distributed build --project <dir or zt_adk.yaml>' first")
    return load_profile(Path(json.loads(PROJECT.read_text())["profile"]))


def deployment() -> D.Deployment:
    if not DEPLOYMENT.exists():
        raise RuntimeError("no deployment descriptor: run 'zt-distributed build' first")
    return D.load(DEPLOYMENT)


def runtime_image(dep_or_name: Any) -> str:
    name = dep_or_name.app_name if hasattr(dep_or_name, "app_name") else str(dep_or_name)
    return f"zt-adk/{D.dns_name(name)}-runtime:dev"


def compose(*args: str, env: dict[str, str] | None = None, check: bool = True, timeout: float | None = 900) -> str:
    dep = deployment()
    return run(["docker", "compose", "-p", dep.compose_project, "-f", str(COMPOSE_FILE), *args], env=env,
               check=check, timeout=timeout).stdout


def P() -> str:
    return deployment().container_prefix


def dexec(container: str, *args: str, user: str | None = None, check: bool = True, timeout: float = 180) -> str:
    cmd = ["docker", "exec"]
    if user:
        cmd += ["-u", user]
    return run(cmd + [f"{P()}{container}", *args], check=check, timeout=timeout).stdout


def http_local(container: str, path: str, timeout: float = 5.0) -> dict[str, Any]:
    code = ("import sys,urllib.request as u;"
            "sys.stdout.write(u.urlopen('http://127.0.0.1:%d'+sys.argv[1],timeout=%s).read().decode())"
            % (D.OPS_PORT, timeout))
    return json.loads(dexec(container, "python", "-c", code, path, timeout=timeout + 30))


def wait_health(container: str, timeout: float = 300) -> dict[str, Any]:
    deadline = time.time() + timeout
    last: Exception | None = None
    while time.time() < deadline:
        try:
            h = http_local(container, "/health")
            if h.get("status") == "ok":
                return h
        except Exception as exc:
            last = exc
        time.sleep(1.0)
    logs = run(["docker", "logs", "--tail", "60", f"{P()}{container}"], check=False)
    raise RuntimeError(f"{container} not healthy after {timeout}s: {last}\n{logs.stdout[-3000:]}{logs.stderr[-3000:]}")


def running_containers() -> list[str]:
    dep = deployment()
    out = run(["docker", "ps", "--filter", f"label=com.docker.compose.project={dep.compose_project}",
               "--format", "{{.Names}}"]).stdout
    return sorted(x.strip() for x in out.splitlines() if x.strip())


# ---------------------------------------------------------------------------- build
def stage_app(prof: Any) -> tuple[Path, dict[str, Any]]:
    """Copy the application (distributed.app_paths) and its staged profile into build/app
    (zt_distributed.staging: app paths outside the profile's directory are supported)."""
    from zt_distributed.staging import stage_application

    dest = BUILD / "app"
    staged = stage_application(prof, Path(json.loads(PROJECT.read_text())["profile"]), dest)
    return dest, staged


def dockerfile(prof: Any, staged: dict[str, Any]) -> Path:
    tpl = (ROOT / "deploy" / "docker" / "runtime.Dockerfile.template").read_text(encoding="utf-8")
    reqs = list(staged["distributed"]["requirements"])          # paths inside the staged application
    copy = "\n".join(f"COPY --from=app {r} /tmp/app-req/{i}-{Path(r).name}" for i, r in enumerate(reqs)) or \
        "# (no requirement files declared: distributed.requirements)"
    pkgs = " ".join(f'"{p}"' for p in prof.distributed.pip_packages)
    install_parts = [f"-r /tmp/app-req/{i}-{Path(r).name}" for i, r in enumerate(reqs)]
    install = ("pip install " + " ".join(install_parts) + (f" {pkgs}" if pkgs else "")) if (install_parts or pkgs) \
        else "true"
    profile_rel = Path(json.loads(PROJECT.read_text())["profile"]).name
    text = tpl.format(python_image=prof.distributed.python_image if prof.distributed.python_image != "python:3.11-slim"
                      else PYTHON_IMAGE_DEFAULT, copy_requirements=copy, install_requirements=install,
                      profile_name=profile_rel)
    out = BUILD / "runtime.Dockerfile"
    out.write_text(text, encoding="utf-8")
    shutil.copy2(ROOT / "deploy" / "docker" / "runtime.Dockerfile.dockerignore", BUILD / "runtime.Dockerfile.dockerignore")
    return out


def build(project: Path | None = None) -> dict[str, Any]:
    if project is not None:
        set_project(project)
    prof = profile()
    app_dir, staged = stage_app(prof)
    df = dockerfile(prof, staged)
    tmp_image = f"zt-adk/{D.dns_name(prof.app_name or Path(prof.base_dir).name)}-runtime:dev"
    log("docker build spire image")
    docker_build(["-f", str(ROOT / "deploy/docker/spire.Dockerfile"), "-t", SPIRE_IMAGE], ROOT)
    log(f"docker build runtime image {tmp_image}")
    docker_build(["-f", str(df), "--build-context", f"app={app_dir}", "-t", tmp_image], BACKPLANE)
    raw = run(["docker", "run", "--rm", tmp_image, "cat", "/opt/describe.json"]).stdout
    desc = json.loads(raw.strip().splitlines()[-1])
    if desc.get("status") == "error":
        raise RuntimeError(f"the application cannot be protected: {desc['errors']}")
    warnings = desc.pop("warnings", [])
    adk = desc.pop("adk_version", None)
    dep = D.Deployment.from_dict(desc)
    image = runtime_image(dep)
    if image != tmp_image:
        run(["docker", "tag", tmp_image, image])
    dep.save(DEPLOYMENT)
    (BUILD / "pip-freeze.txt").write_text(run(["docker", "run", "--rm", image, "cat", "/opt/pip-freeze.txt"]).stdout)
    for svc in dep.user_services:
        if svc.get("build"):
            ctx = prof.path(svc["build"])
            args = ["-t", f"zt-adk/{D.dns_name(svc['name'])}:dev"]
            if svc.get("dockerfile"):
                args += ["-f", str(prof.path(svc["dockerfile"]))]
            log(f"docker build service {svc['name']}")
            docker_build(args, ctx)
    gen_compose()
    return {"app": dep.app_name, "agents": len(dep.agents), "entry_agents": dep.entry_agents, "adk_version": adk,
            "runtime_image": image, "warnings": warnings, "image_id": image_id(image)}


def image_id(image: str) -> str:
    return run(["docker", "image", "inspect", image, "--format", "{{.Id}}"], check=False).stdout.strip()


# ---------------------------------------------------------------------------- compose
def _secret(subpath: str, target: str) -> dict[str, Any]:
    return {"type": "volume", "source": "secrets", "target": target, "read_only": True,
            "volume": {"subpath": subpath, "nocopy": True}}


def gen_compose() -> Path:
    dep = deployment()
    prof = profile()
    image = runtime_image(dep)
    pre = dep.container_prefix
    live = "/results/live"
    td = dep.trust_domain
    dep_mount = "./deployment.json:/etc/zt/deployment.json:ro"
    common = ["spire-sockets:/run/spire/sockets:ro", "../results:/results", dep_mount]

    def env(extra: dict[str, str]) -> dict[str, str]:
        e = {"SPIFFE_ENDPOINT_SOCKET": "unix:///run/spire/sockets/agent.sock", "ZT_TRUST_DOMAIN": td,
             "CONN_MODE": "${CONN_MODE:-reuse}", "TLS_SESSION_TICKETS": "${TLS_SESSION_TICKETS:-on}",
             "AGENT_RENEW_FRACTION": "${AGENT_RENEW_FRACTION:-0.5}", "HOME": "/tmp"}
        e.update(extra)
        return e

    def service(name: str, *, uid: int, command: list[str], environment: dict[str, str], volumes: list[Any],
                limits: tuple[str, str], env_file: list[str] | None = None) -> dict[str, Any]:
        s: dict[str, Any] = {"image": image, "container_name": f"{pre}{name}", "hostname": name,
                             "user": f"{uid}:{uid}", "labels": {D.LABEL_KEY: name}, "networks": [NET],
                             "environment": environment, "command": command, "volumes": volumes,
                             "cpus": limits[0], "mem_limit": limits[1], "stop_grace_period": "5s", "init": True}
        if env_file:
            s["env_file"] = env_file
        return s

    env_files = [str(prof.path(f)) for f in prof.distributed.secret_env_files]
    tool_env_files = [str(prof.path(f)) for f in prof.distributed.tool_host_secret_env_files]
    for f in env_files + tool_env_files:
        if not Path(f).is_file():
            raise FileNotFoundError(f"secret env file not found: {f}")
    data_vols = [f"{v}:{m}" for v, m in prof.distributed.data_volumes.items()]
    services: dict[str, Any] = {}
    services["spire-server"] = {
        "image": SPIRE_IMAGE, "container_name": f"{pre}spire-server", "hostname": "spire-server", "networks": [NET],
        "command": ["spire-server", "run", "-config", "/etc/spire/server.conf"],
        "volumes": ["./spire/server.conf:/etc/spire/server.conf:ro", "./public/spire/node_ca.pem:/etc/spire/node_ca.pem:ro",
                    "./public/spire/entries.json:/etc/spire/entries.json:ro",
                    "../deploy/spire/register.py:/opt/register.py:ro", "spire-server-data:/var/lib/spire/server"],
        "cpus": LIMITS["spire-server"][0], "mem_limit": LIMITS["spire-server"][1], "labels": {D.LABEL_KEY: "spire-server"}}
    services["spire-agent"] = {
        "image": SPIRE_IMAGE, "container_name": f"{pre}spire-agent", "hostname": "spire-agent", "networks": [NET],
        "pid": "host", "command": ["spire-agent", "run", "-config", "/etc/spire/agent.conf"],
        "volumes": ["./spire/agent.conf:/etc/spire/agent.conf:ro",
                    "./public/spire/bootstrap_bundle.pem:/etc/spire/bootstrap_bundle.pem:ro",
                    "/var/run/docker.sock:/var/run/docker.sock:ro", "spire-sockets:/run/spire/sockets",
                    "spire-agent-data:/var/lib/spire/agent", _secret("spire-node", "/run/secrets/spire-node")],
        "cpus": LIMITS["spire-agent"][0], "mem_limit": LIMITS["spire-agent"][1], "labels": {D.LABEL_KEY: "spire-agent"}}
    gw = dep.gateway
    services["zt-gateway"] = service(
        "zt-gateway", uid=gw.uid, command=["python", "-m", "zt_distributed.gateway"],
        environment=env({**prof.distributed.tool_host_environment, "ZT_EVENTS_FILE": f"{live}/zt-gateway.events.jsonl",
                         "ZT_SPANS_FILE": f"{live}/zt-gateway.spans.jsonl", "ZT_COMPONENT": "zt-gateway"}),
        volumes=common + data_vols + [
            _secret("zt-keys", "/run/secrets/zt-keys"), "./public/bundle:/public/bundle:ro",
            "./public/config:/etc/zt/config:ro", "./public/agent-ca:/etc/zt/agent-ca:ro",
            "./state/gateway:/var/lib/zt-gateway/state", "./state/approvals:/var/lib/zt-gateway/approvals"],
        limits=LIMITS["zt-gateway"], env_file=tool_env_files or None)
    iss = dep.issuer
    services["agent-issuer"] = service(
        "agent-issuer", uid=iss.uid,
        command=["python", "-m", "zt_identity.agent_identity.issuer", "--trust-domain", td,
                 "--ca-cert", "/etc/zt/agent-ca/ca.pem", "--registry", "/etc/zt/config/agent_registry.json",
                 "--gateway-spiffe-id", gw.spiffe_id],
        environment=env({"AGENT_CERT_TTL_SECONDS": "${AGENT_CERT_TTL_SECONDS:-86400}",
                         "ZT_EVENTS_FILE": f"{live}/agent-issuer.events.jsonl", "ZT_COMPONENT": "agent-issuer"}),
        volumes=common + ["issuer-state:/var/lib/agent-issuer", _secret("agent-ca", "/run/secrets/agent-ca"),
                          "./public/config:/etc/zt/config:ro", "./public/agent-ca:/etc/zt/agent-ca:ro"],
        limits=LIMITS["agent-issuer"])
    ing = dep.ingress
    services["ingress-client"] = service("ingress-client", uid=ing.uid, command=["sleep", "infinity"],
                                         environment=env({"ZT_COMPONENT": "ingress-client"}), volumes=common,
                                         limits=LIMITS["ingress-client"])
    for agent_id, w in dep.agents.items():
        services[w.name] = service(
            w.name, uid=w.uid, command=["python", "-m", "zt_distributed.agent_service"],
            environment=env({**prof.distributed.environment, "AGENT_ID": agent_id, "ZT_COMPONENT": w.name,
                             "ZT_EVENTS_FILE": f"{live}/{w.name}.events.jsonl",
                             "ZT_SPANS_FILE": f"{live}/{w.name}.spans.jsonl"}),
            volumes=common + [_secret(f"agents/{agent_id}", "/run/secrets/agent-enroll")],
            limits=LIMITS["agent"], env_file=env_files or None)
    for svc in dep.user_services:
        s: dict[str, Any] = {"container_name": f"{pre}{svc['name']}", "hostname": svc["name"], "networks": [NET],
                             "environment": dict(svc.get("environment") or {}), "labels": {D.LABEL_KEY: svc["name"]}}
        s["image"] = svc.get("image") or f"zt-adk/{D.dns_name(svc['name'])}:dev"
        if svc.get("healthcheck"):
            s["healthcheck"] = {"test": svc["healthcheck"], "interval": "2s", "retries": 60}
        services[svc["name"]] = s
    services["ops"] = {
        "image": image, "container_name": f"{pre}ops", "profiles": ["ops"], "networks": [NET], "user": "0:0",
        "command": ["true"], "environment": {"HOME": "/tmp", "ZT_DEPLOYMENT": "/etc/zt/deployment.json",
                                             "ZT_APPROVERS": "${ZT_APPROVERS:-approver}",
                                             "ZT_SECONDARIES": "${ZT_SECONDARIES:-}"},
        "volumes": ["secrets:/secrets", "./public:/public", "./approver-keys:/approvers", dep_mount,
                    "issuer-state:/var/lib/agent-issuer", "../results:/results"] + data_vols}
    services["tool-setup"] = {
        "image": image, "container_name": f"{pre}tool-setup", "profiles": ["ops"], "networks": [NET],
        "user": f"{gw.uid}:{gw.uid}", "command": ["true"],
        "environment": {"HOME": "/tmp", **prof.distributed.tool_host_environment}, "volumes": data_vols}
    if tool_env_files:
        services["tool-setup"]["env_file"] = tool_env_files
    volumes = {v: {} for v in ["spire-server-data", "spire-agent-data", "spire-sockets", "secrets", "issuer-state",
                               *prof.distributed.data_volumes]}
    compose_doc = {"name": dep.compose_project, "services": services, "networks": {NET: {"driver": "bridge"}},
                   "volumes": volumes}
    COMPOSE_FILE.write_text("# GENERATED by zt-distributed (zt_distributed.stack) - do not edit\n"
                            + json.dumps(compose_doc, indent=1) + "\n", encoding="utf-8")
    return COMPOSE_FILE


# ---------------------------------------------------------------------------- prepare
def prepare() -> dict[str, Any]:
    dep = deployment()
    prof = profile()
    gen_compose()
    (RUNTIME / "spire").mkdir(parents=True, exist_ok=True)
    for name in ("server.conf", "agent.conf"):
        text = (ROOT / "deploy" / "spire" / name).read_text(encoding="utf-8").replace("__TRUST_DOMAIN__", dep.trust_domain)
        (RUNTIME / "spire" / name).write_text(text, encoding="utf-8")
    (PUBLIC / "spire").mkdir(parents=True, exist_ok=True)
    (PUBLIC / "spire" / "bootstrap_bundle.pem").touch()
    for d in (APPROVERS, STATE / "gateway", STATE / "approvals", LIVE):
        d.mkdir(parents=True, exist_ok=True)
    # a new node CA and new trust material invalidate the SPIRE server's and agents' stored state
    # (a different trust domain would even stop the server): start SPIRE from empty data volumes
    compose("--profile", "ops", "down", check=False, timeout=300)
    for vol in ("spire-server-data", "spire-agent-data", "spire-sockets", "issuer-state"):
        run(["docker", "volume", "rm", "-f", f"{dep.compose_project}_{vol}"], check=False)
    out = compose("--profile", "ops", "run", "--rm", "ops", "python", "-m", "zt_distributed.prepare", timeout=1800)
    result = {"prepare": json.loads(out.strip().splitlines()[-1])}
    mounts = list(prof.distributed.data_volumes.values())
    if mounts:                       # the tool host (gateway user) owns the application's data volumes
        uid = dep.gateway.uid
        compose("--profile", "ops", "run", "--rm", "ops", "sh", "-c",
                " && ".join(f"mkdir -p {m} && chown -R {uid}:{uid} {m}" for m in mounts))
    if prof.distributed.setup_command:
        result["setup"] = compose("--profile", "ops", "run", "--rm", "tool-setup", *prof.distributed.setup_command,
                                  timeout=1800).strip().splitlines()[-5:]
    return result


# ---------------------------------------------------------------------------- SPIRE / start / stop
def spire_up(svid_ttl: int = 0) -> dict[str, Any]:
    t0 = time.time()
    compose("up", "-d", "spire-server")
    deadline = time.time() + 90
    while True:
        p = run(["docker", "exec", f"{P()}spire-server", "spire-server", "healthcheck", "-socketPath", SPIRE_SOCK],
                check=False)
        if p.returncode == 0:
            break
        if time.time() > deadline:
            raise RuntimeError("spire-server not healthy: " + p.stderr)
        time.sleep(1)
    bundle = run(["docker", "exec", f"{P()}spire-server", "spire-server", "bundle", "show", "-socketPath",
                  SPIRE_SOCK]).stdout
    (PUBLIC / "spire" / "bootstrap_bundle.pem").write_text(bundle)
    reg = json.loads(run(["docker", "exec", f"{P()}spire-server", "python3", "/opt/register.py", "--x509-ttl",
                          str(svid_ttl)]).stdout)
    compose("up", "-d", "spire-agent")
    deadline = time.time() + 90
    while True:
        p = run(["docker", "exec", f"{P()}spire-agent", "spire-agent", "healthcheck", "-socketPath",
                 "/run/spire/sockets/agent.sock"], check=False)
        if p.returncode == 0:
            break
        if time.time() > deadline:
            raise RuntimeError("spire-agent not healthy: " + p.stderr)
        time.sleep(1)
    return {"spire_ready_s": round(time.time() - t0, 3), "registration": {k: v for k, v in reg.items() if k != "entries"}}


def _wait_issuer(timeout: float = 90) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        p = run(["docker", "exec", f"{P()}agent-issuer", "python", "-c",
                 "import os,sys;sys.exit(0 if os.path.exists('/var/lib/agent-issuer/admin/admin.sock') else 1)"],
                check=False)
        if p.returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError("agent-issuer did not become ready")


def start(*, svid_ttl: int = 0, agent_cert_ttl: int = 86400, conn_mode: str = "reuse") -> dict[str, Any]:
    dep = deployment()
    agents = [w.name for w in dep.agents.values()]
    env = {"CONN_MODE": conn_mode, "AGENT_CERT_TTL_SECONDS": str(agent_cert_ttl)}
    info: dict[str, Any] = {"agents": len(agents)}
    t0 = time.time()
    compose("stop", "ingress-client", "zt-gateway", "agent-issuer", *agents, check=False)
    info["spire"] = spire_up(svid_ttl)
    # The live event/span logs are a shared bind mount: a file left by another deployment (e.g. another
    # application with an agent of the same name) belongs to a different uid. Each component owns its
    # own files under this deployment's uids, or it cannot append to them.
    owners = [("zt-gateway", dep.gateway.uid), ("agent-issuer", dep.issuer.uid)] + \
             [(w.name, w.uid) for w in dep.agents.values()]
    chown_live = "; ".join(f"for f in /results/live/{n}.events.jsonl /results/live/{n}.spans.jsonl; do "
                           f"[ -e $f ] && chown {u}:{u} $f; done" for n, u in owners)
    LIVE.mkdir(parents=True, exist_ok=True)
    run(["docker", "run", "--rm", "-u", "0:0", "-v", f"{dep.compose_project}_issuer-state:/s",
         "-v", f"{RESULTS}:/results", runtime_image(dep),
         "sh", "-c", f"rm -rf /s/state.json /s/admin; chown -R {dep.issuer.uid}:{dep.issuer.uid} /s; "
                     f"{chown_live}; true"], check=False)
    compose("up", "-d", "--force-recreate", "agent-issuer", env=env)
    _wait_issuer()
    user_services = [s["name"] for s in dep.user_services]
    compose("up", "-d", "--force-recreate", *user_services, "zt-gateway", env=env)
    info["gateway"] = wait_health("zt-gateway")
    compose("up", "-d", "--force-recreate", *agents, "ingress-client", env=env)
    info["agent_health"] = {a: wait_health(a)["status"] for a in agents}
    info["start_total_s"] = round(time.time() - t0, 3)
    return info


def status() -> dict[str, Any]:
    names = running_containers()
    out: dict[str, Any] = {"running": names}
    pre = P()
    for n in names:
        short = n.removeprefix(pre)
        if short == "zt-gateway" or short.startswith("wl-"):
            try:
                h = http_local(short, "/health")
                out[short] = {k: h.get(k) for k in ("status", "agent_id", "policy_version", "logical_peps")}
            except Exception as exc:
                out[short] = {"health_error": str(exc)[-200:]}
    return out


def ingress(*args: str, timeout: float = 1800) -> dict[str, Any]:
    out = dexec("ingress-client", "python", "-m", "zt_distributed.ingress_client", *args, timeout=timeout)
    return json.loads([ln for ln in out.strip().splitlines() if ln.startswith("{")][-1])


def gateway_stats() -> dict[str, Any]:
    return http_local("zt-gateway", "/stats", timeout=30)


def issuer_admin(action: str, agent_id: str) -> dict[str, Any]:
    return json.loads(dexec("agent-issuer", "python", "-m", "zt_identity.agent_identity.admin", action, agent_id))


def verify() -> dict[str, Any]:
    from zt_distributed.verify_state import verify as verify_state

    return verify_state(STATE / "gateway")


def stop_all(purge: bool = False) -> None:
    if not COMPOSE_FILE.exists():
        return
    compose("--profile", "ops", "down", *(["-v"] if purge else []), check=False, timeout=300)


def reset_state() -> None:
    """Fresh audit / decision logs and approval store for the next start (data volumes untouched)."""
    for d in (STATE / "gateway", STATE / "approvals"):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True, exist_ok=True)


def approvals_store() -> Any:
    from zt_adk.approvals import ApprovalStore

    return ApprovalStore(STATE / "approvals")


def approver_key(name: str, secondary: bool) -> Any:
    from zt_adk.keys import approver_issuer, load_private
    from zt_pdp.evidence_issuer import IssuerKey

    prefix = "secondary" if secondary else "approver"
    return IssuerKey(approver_issuer(name, secondary), "key-1", load_private(APPROVERS / f"{prefix}_{name}_private.pem"))


def wait_for_approval(timeout: float = 120) -> Any:
    deadline = time.time() + timeout
    store = approvals_store()
    while time.time() < deadline:
        pending = store.list(status="pending")
        if pending:
            return pending[0]
        time.sleep(0.5)
    return None


def logs(container: str, tail: int = 80) -> str:
    p = run(["docker", "logs", "--tail", str(tail), f"{P()}{container}"], check=False)
    return (p.stdout or "") + (p.stderr or "")


def iter_agents() -> Iterable[str]:
    return [w.name for w in deployment().agents.values()]
