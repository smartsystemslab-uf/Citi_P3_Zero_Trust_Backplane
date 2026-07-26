from pathlib import Path

import pytest

from zt_backplane.policy_store import PolicyBundle


def test_duplicate_policy_ids_are_rejected(tmp_path: Path):
    (tmp_path / "a.yaml").write_text(
        """
policies:
  - id: DUPLICATE
    effect: ALLOW
    match: {}
""",
        encoding="utf-8",
    )
    (tmp_path / "b.yaml").write_text(
        """
policies:
  - id: DUPLICATE
    effect: DENY
    match: {}
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate policy id"):
        PolicyBundle.load(tmp_path)


def test_unsupported_match_key_is_rejected(tmp_path: Path):
    (tmp_path / "bad.yaml").write_text(
        """
policies:
  - id: BAD
    effect: ALLOW
    match:
      python_expression: subject == 'x'
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unsupported match keys"):
        PolicyBundle.load(tmp_path)
