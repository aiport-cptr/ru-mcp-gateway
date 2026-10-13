"""Независимая проверка 0.4.5: только временные файлы и поддельный Docker."""

import os
import shutil
import subprocess
from pathlib import Path


def test_failed_backup_with_same_timestamp_preserves_existing_copy(tmp_path):
    root = Path(__file__).resolve().parents[1]
    deploy = tmp_path / "deploy"
    deploy.mkdir()
    for name in ("backup.sh", "lib.sh"):
        shutil.copy2(root / "deploy" / name, deploy / name)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    scripts = {
        "date": "#!/bin/sh\nprintf '%s\\n' '20261013-120000'\n",
        "docker": (
            "#!/bin/sh\n"
            'if [ "$1 $2 $3" = "compose exec -T" ]; then\n'
            "  printf 'synthetic-partial-dump'\n"
            "  exit 1\n"
            "fi\n"
            "exit 0\n"
        ),
    }
    for name, source in scripts.items():
        path = fake_bin / name
        path.write_text(source)
        path.chmod(0o755)
    backups = tmp_path / "backups"
    backups.mkdir()
    previous = backups / "rugw-20261013-120000.dump"
    previous.write_bytes(b"synthetic-previous-successful-dump")
    env = {**os.environ, "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}"}
    result = subprocess.run(  # noqa: S603 — запускается копия скрипта репозитория, все параметры заданы тестом
        ["/bin/bash", str(deploy / "backup.sh")], env=env, capture_output=True, text=True, timeout=10
    )
    assert result.returncode != 0  # ошибка pg_dump обязана остановить скрипт
    assert previous.is_file(), "failed backup deleted the existing successful copy"
    assert previous.read_bytes() == b"synthetic-previous-successful-dump"
