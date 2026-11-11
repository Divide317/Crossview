"""Python-side tests: ABI agreement, a live scan, schema validation, CLI exit codes."""
import json
import pathlib
import subprocess
import sys

import crossview
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "schema" / "crossview-report.schema.json").read_text())


@pytest.fixture(scope="module")
def lib():
    return crossview.Library()


def test_abi_and_config_size(lib):
    # Library() raises ImportError if the ABI or cv_config size disagree.
    assert lib.version


def test_scan_validates_against_schema(lib):
    jsonschema = pytest.importorskip("jsonschema")
    report = lib.scan(pid_max=65536, recheck_delay_ms=10)
    jsonschema.Draft202012Validator(SCHEMA).validate(report)
    views = {v["view"] for v in report["views"]}
    assert {"proc_readdir", "proc_getdents", "pid_kill", "pid_stat"} <= views
    assert "bind_probe" not in views          # opt-in
    assert report["host"]["syscall_dispatch"] in {"table", "switch", "unknown"}


def test_clean_host_has_no_mismatches(lib):
    report = lib.scan(["processes"], pid_max=65536, recheck_delay_ms=10)
    bad = [f for f in report["findings"] if f["type"] == "mismatch" and f["confidence"] != "low"]
    assert bad == [], bad


def test_unknown_check_rejected(lib):
    with pytest.raises(ValueError):
        lib.scan(["nonsense"])


def test_cli_exit_codes():
    r = subprocess.run([sys.executable, "-m", "crossview", "scan", "--checks", "processes",
                        "--pid-max", "65536", "--json"],
                       cwd=ROOT / "python", capture_output=True, text=True, check=False)
    assert r.returncode in (0, 1), r.stderr
    json.loads(r.stdout)
    r = subprocess.run([sys.executable, "-m", "crossview", "scan", "--checks", "bogus"],
                       cwd=ROOT / "python", capture_output=True, text=True, check=False)
    assert r.returncode == 2
