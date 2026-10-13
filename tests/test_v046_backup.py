"""0.4.6: deploy/backup.sh — копии не перезаписываются и не теряются (поддельный Docker, временные файлы)."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

DOCKER_OK = """#!/bin/sh
case "$*" in
  *pg_dump*) printf 'synthetic-dump' ;;
  *pg_restore*) cat >/dev/null ;;
esac
exit 0
"""
DOCKER_BAD_ARCHIVE = DOCKER_OK.replace("*pg_restore*) cat >/dev/null ;;", "*pg_restore*) cat >/dev/null; exit 1 ;;")


def setup(tmp_path, docker: str, stamp: str = "20261013-120000") -> tuple[Path, dict]:
    deploy = tmp_path / "deploy"
    deploy.mkdir()
    for name in ("backup.sh", "lib.sh"):
        shutil.copy2(ROOT / "deploy" / name, deploy / name)
    fake = tmp_path / "bin"
    fake.mkdir()
    for name, src in {"date": f"#!/bin/sh\nprintf '%s\\n' '{stamp}'\n", "docker": docker}.items():
        (fake / name).write_text(src)
        (fake / name).chmod(0o755)
    (tmp_path / "backups").mkdir()
    return tmp_path, {**os.environ, "PATH": f"{fake}{os.pathsep}{os.environ['PATH']}"}


def run(root: Path, env: dict, **extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 — копия скрипта репозитория, параметры заданы тестом
        ["/bin/bash", str(root / "deploy" / "backup.sh")],
        env={**env, **extra},
        capture_output=True,
        text=True,
        timeout=20,
    )


def dumps(root: Path) -> list[str]:
    return sorted(p.name for p in (root / "backups").iterdir() if p.name.endswith(".dump"))


def test_same_second_gets_new_name_and_keeps_old(tmp_path):
    root, env = setup(tmp_path, DOCKER_OK)
    old = root / "backups" / "rugw-20261013-120000.dump"
    old.write_bytes(b"previous")
    r = run(root, env)
    assert r.returncode == 0, r.stderr
    assert old.read_bytes() == b"previous"
    assert dumps(root) == ["rugw-20261013-120000-2.dump", "rugw-20261013-120000.dump"]
    new = root / "backups" / "rugw-20261013-120000-2.dump"
    assert new.read_bytes() == b"synthetic-dump" and oct(new.stat().st_mode & 0o777) == "0o600"
    assert not [p for p in (root / "backups").iterdir() if p.name.endswith(".part")]  # временный файл убран


def test_unreadable_archive_is_not_published(tmp_path):
    root, env = setup(tmp_path, DOCKER_BAD_ARCHIVE)
    r = run(root, env)
    assert r.returncode != 0
    assert dumps(root) == [] and not [p for p in (root / "backups").iterdir() if p.name.endswith(".part")]


def test_retention_runs_only_after_success_and_keeps_newest(tmp_path):
    root, env = setup(tmp_path, DOCKER_OK, stamp="20261013-130000")
    for i in range(3):
        p = root / "backups" / f"rugw-2026100{i + 1}-000000.dump"
        p.write_bytes(b"x")
        os.utime(p, (1_700_000_000 + i, 1_700_000_000 + i))
    (root / "backups" / "notes.txt").write_text("не наш файл")
    r = run(root, env, KEEP="2")
    assert r.returncode == 0, r.stderr
    assert dumps(root) == ["rugw-20261003-000000.dump", "rugw-20261013-130000.dump"]
    assert (root / "backups" / "notes.txt").exists()


def test_failed_dump_does_not_rotate(tmp_path):
    bad = DOCKER_OK.replace("*pg_dump*) printf 'synthetic-dump' ;;", "*pg_dump*) exit 1 ;;")
    root, env = setup(tmp_path, bad)
    for i in range(3):
        (root / "backups" / f"rugw-2026100{i + 1}-000000.dump").write_bytes(b"x")
    r = run(root, env, KEEP="1")
    assert r.returncode != 0
    assert len(dumps(root)) == 3


@pytest.mark.parametrize("keep", ["0", "abc", "-1"])
def test_keep_validated(tmp_path, keep):
    root, env = setup(tmp_path, DOCKER_OK)
    r = run(root, env, KEEP=keep)
    assert r.returncode != 0 and dumps(root) == []
