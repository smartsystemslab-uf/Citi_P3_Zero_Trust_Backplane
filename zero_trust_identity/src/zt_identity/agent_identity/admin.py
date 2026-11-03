"""Issuer admin CLI (scheme B). Runs INSIDE the agent-issuer container and
talks to the issuer over its private unix socket (0700 dir, owner-only).

    python -m auth.agent_identity.admin disable <agent_id>
    python -m auth.agent_identity.admin enable  <agent_id>
    python -m auth.agent_identity.admin stats
"""
from __future__ import annotations

import asyncio
import json
import sys

import aiohttp

SOCKET = "/var/lib/agent-issuer/admin/admin.sock"


async def main(argv: list[str]) -> int:
    conn = aiohttp.UnixConnector(path=SOCKET)
    async with aiohttp.ClientSession(connector=conn) as s:
        if argv[0] == "stats":
            async with s.get("http://issuer/admin/stats") as r:
                print(json.dumps(await r.json()))
                return 0 if r.status == 200 else 1
        action, agent_id = argv[0], argv[1]
        async with s.post(f"http://issuer/admin/agents/{agent_id}/{action}") as r:
            print(json.dumps(await r.json()))
            return 0 if r.status == 200 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1:])))
