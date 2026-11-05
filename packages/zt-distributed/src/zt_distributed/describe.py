"""Print the deployment descriptor of the application in this image (run inside the runtime image).

    python -m zt_distributed.describe            JSON on stdout (the host stores runtime/deployment.json)

Imports the application exactly as the workloads will, discovers its agent tree and fails if
discovery finds anything the Backplane could not protect.
"""
from __future__ import annotations

import json
import sys

from .appload import load_app
from .deployment import describe


def main() -> int:
    app = load_app(resolve_toolsets=True, apply_model_override=False)
    if app.model.errors:
        print(json.dumps({"status": "error", "errors": app.model.errors}), flush=True)
        return 2
    dep = describe(app.model, app.profile)
    out = dep.to_dict()
    out["warnings"] = app.model.warnings
    out["adk_version"] = app.model.adk_version
    print(json.dumps(out, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
