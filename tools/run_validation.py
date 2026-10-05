#!/usr/bin/env python3
"""Build and verify source, unpacked sdist, and isolated installed wheel."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
import zipfile
from email import message_from_bytes
from email.policy import default
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "Build"
VERSION = "0.1.0"
DIST_ROOT = f"obfuscated_string_recovery-{VERSION}"
DOCS = ROOT / "项目文档"
PACKAGE_FILES = {
    "obfuscated_string_recovery/__init__.py",
    "obfuscated_string_recovery/__main__.py",
    "obfuscated_string_recovery/scanner.py",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def invoke(label: str, argv: list[str], cwd: Path, env: dict[str, str],
           expected: int = 0) -> str:
    process = subprocess.run(argv, cwd=cwd, env=env, text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             timeout=120, check=False)
    (BUILD / f"{label}.log").write_text(process.stdout)
    if process.returncode != expected:
        raise RuntimeError(f"{label}: exit {process.returncode}, expected {expected}")
    return process.stdout


def source_manifest() -> dict[str, str]:
    result = {}
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if relative.parts[0] == ".git":
            continue
        if relative.parts[0] == "Build" and relative != Path("Build/.gitignore"):
            continue
        result[str(relative)] = sha(path)
    return result


def run_mode(mode: str, project: Path, python: Path, base_env: dict[str, str],
             fixture: Path) -> dict:
    env = dict(base_env)
    if mode in ("source", "sdist"):
        env["PYTHONPATH"] = str(project / "src")
    else:
        env.pop("PYTHONPATH", None)
    tests = project / "tests"
    unit_log = invoke(f"{mode}-tests", [str(python), "-W", "error::ResourceWarning",
                                       "-m", "unittest", "discover", "-s", str(tests),
                                       "-v"], project, env)
    if "Ran 5 tests" not in unit_log or "\nOK\n" not in unit_log:
        raise RuntimeError(f"{mode}: missing expected unit results")
    output = invoke(f"{mode}-cli", [str(python), "-m",
                                    "obfuscated_string_recovery", str(fixture)],
                    project, env)
    report = json.loads(output)
    if report["status"] != "PASS_STATIC_ONLY" or report["counts"]["findings"] != 2:
        raise RuntimeError(f"{mode}: static scanner report failed")
    findings = {row["value"]: row for row in report["findings"]}
    if set(findings) != {"HELLO", "WORLD"} or findings["WORLD"]["classification"] != "decoded":
        raise RuntimeError(f"{mode}: recovered values incorrect")
    raw = fixture.read_bytes()
    for finding in findings.values():
        if len(finding["byte_provenance"]) != len(finding["value"]) + 1:
            raise RuntimeError(f"{mode}: byte provenance missing")
        if any(raw[item["initial_file_offset"]:item["initial_file_offset"] + 2] != b"\xc6\x45"
               for item in finding["byte_provenance"]):
            raise RuntimeError(f"{mode}: origin offset does not point to a byte write")
    if not 0 <= report["elapsed_ms"] <= report["limits"]["max_wall_ms"]:
        raise RuntimeError(f"{mode}: elapsed-time budget not satisfied")
    if "unknown_branch" not in {item["function"] for item in report["skipped_functions"]}:
        raise RuntimeError(f"{mode}: unknown control flow was not skipped")
    budget_output = invoke(
        f"{mode}-budget-cli",
        [str(python), "-m", "obfuscated_string_recovery", str(fixture),
         "--max-instructions", "10"],
        project, env, expected=3,
    )
    if json.loads(budget_output)["status"] != "BUDGET_EXCEEDED":
        raise RuntimeError(f"{mode}: command-line budget rejection missing")
    return {
        "unit_tests": 5,
        "unit_log_sha256": sha(BUILD / f"{mode}-tests.log"),
        "cli_log_sha256": sha(BUILD / f"{mode}-cli.log"),
        "budget_cli_log_sha256": sha(BUILD / f"{mode}-budget-cli.log"),
        "status": report["status"],
        "elapsed_ms": report["elapsed_ms"],
        "values": sorted(findings),
        "function_offsets": {
            value: {
                "function_section_offset": finding["function_section_offset"],
                "first_initial_file_offset": finding["byte_provenance"][0]["initial_file_offset"],
                "transform_file_offsets": finding["transform_file_offsets"],
            }
            for value, finding in findings.items()
        },
        "skipped_functions": report["skipped_functions"],
    }


def main() -> None:
    BUILD.mkdir(exist_ok=True)
    if any((ROOT / name).exists() for name in ("README.md", "LICENSE")):
        raise RuntimeError("root documents must be under 项目文档")
    for name in ("README.md", "LICENSE", "ORIGIN.md", "项目说明.md"):
        if not (DOCS / name).is_file():
            raise RuntimeError(f"missing project document {name}")
    if not (BUILD / ".gitignore").is_file():
        raise RuntimeError("Build marker absent")
    for name in ("dist", "stage", "venv", "consumer", "fixtures"):
        path = BUILD / name
        if path.exists():
            shutil.rmtree(path)
        path.mkdir()
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PIP_CACHE_DIR"] = str(BUILD / "pip-cache")
    env["TMPDIR"] = str(BUILD / "fixtures")
    python = Path(sys.executable).absolute()

    compile_start = time.monotonic()
    fixture = BUILD / "fixtures/stack_strings.o"
    invoke("compile-fixture", [
        "clang", "-target", "x86_64-unknown-linux-gnu", "-O0",
        "-fno-stack-protector", "-fno-omit-frame-pointer", "-c",
        str(ROOT / "tests/fixtures/stack_strings.c"), "-o", str(fixture),
    ], ROOT, env)
    if not fixture.read_bytes().startswith(b"\x7fELF"):
        raise RuntimeError("fixture compiler did not produce ELF")
    fixture_compile_ms = round((time.monotonic() - compile_start) * 1000, 3)

    invoke("package-build", [str(python), "-m", "build", "--no-isolation",
                             "--outdir", str(BUILD / "dist"), str(ROOT)], ROOT, env)
    sdists = list((BUILD / "dist").glob("*.tar.gz"))
    wheels = list((BUILD / "dist").glob("*.whl"))
    if len(sdists) != 1 or len(wheels) != 1:
        raise RuntimeError("expected exactly one sdist and one wheel")
    sdist, wheel = sdists[0], wheels[0]
    if sdist.name != f"{DIST_ROOT}.tar.gz" or wheel.name != f"{DIST_ROOT}-py3-none-any.whl":
        raise RuntimeError("package version or names incorrect")

    with tarfile.open(sdist, "r:gz") as archive:
        members = archive.getmembers()
        names = [item.name for item in members]
        if any(not (item.isfile() or item.isdir()) for item in members):
            raise RuntimeError("unsupported source archive member type")
        if any(not name.startswith(f"{DIST_ROOT}/") or ".." in Path(name).parts
               or Path(name).is_absolute() for name in names):
            raise RuntimeError("unsafe or mismatched source archive member")
        archive.extractall(BUILD / "stage")
    stage = BUILD / "stage" / DIST_ROOT
    for name in ("README.md", "LICENSE", "ORIGIN.md", "项目说明.md"):
        if (stage / "项目文档" / name).read_bytes() != (DOCS / name).read_bytes():
            raise RuntimeError(f"sdist project document mismatch: {name}")
    if not (stage / "tests/fixtures/stack_strings.c").is_file():
        raise RuntimeError("self-owned fixture source missing from sdist")
    if any((stage / name).exists() for name in ("README.md", "LICENSE")):
        raise RuntimeError("root documents leaked into sdist")

    with zipfile.ZipFile(wheel) as archive:
        wheel_names = archive.namelist()
        actual_package = {name for name in wheel_names
                          if name.startswith("obfuscated_string_recovery/")}
        if actual_package != PACKAGE_FILES:
            raise RuntimeError("wheel package file allowlist mismatch")
        if any("tests/" in name or "weak_baseline" in name or "fixtures/" in name
               for name in wheel_names):
            raise RuntimeError("test-only material leaked into installed wheel")
        metadata = message_from_bytes(
            archive.read(f"{DIST_ROOT}.dist-info/METADATA"), policy=default
        )
        license_path = f"{DIST_ROOT}.dist-info/licenses/项目文档/LICENSE"
        if license_path not in wheel_names or archive.read(license_path) != (DOCS / "LICENSE").read_bytes():
            raise RuntimeError("wheel license absent or changed")
    if (metadata["Name"] != "obfuscated-string-recovery" or
            metadata["Version"] != VERSION or metadata["Author"] != "dhtfish98" or
            metadata["License-Expression"] != "MIT" or
            "项目文档/LICENSE" not in metadata.get_all("License-File", []) or
            "# ObfuscatedStringRecovery" not in metadata.get_payload()):
        raise RuntimeError("wheel metadata identity or rights mismatch")

    invoke("venv-create", [str(python), "-m", "venv", str(BUILD / "venv")], BUILD, env)
    installed_python = BUILD / "venv/bin/python"
    invoke("wheel-install", [str(installed_python), "-m", "pip", "install",
                             "--no-index", "--no-deps", str(wheel)], BUILD, env)
    shutil.copytree(stage / "tests", BUILD / "consumer/tests")
    imported = invoke("installed-import", [str(installed_python), "-c",
                                            "import obfuscated_string_recovery as p; print(p.__file__)"],
                      BUILD / "consumer", {key: value for key, value in env.items()
                                            if key != "PYTHONPATH"}).strip()
    if not imported.startswith(str(BUILD / "venv")):
        raise RuntimeError("installed mode imported repository source")

    modes = {
        "source": run_mode("source", ROOT, python, env, fixture),
        "sdist": run_mode("sdist", stage, python, env, fixture),
        "installed": run_mode("installed", BUILD / "consumer", installed_python,
                              env, fixture),
    }
    manifest = source_manifest()
    digest = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    checks = {
        "all_three_modes_pass": all(mode["status"] == "PASS_STATIC_ONLY" and
                                    mode["unit_tests"] == 5 for mode in modes.values()),
        "plain_and_decoded_values_with_offsets": all(
            mode["values"] == ["HELLO", "WORLD"] and
            len(mode["function_offsets"]["WORLD"]["transform_file_offsets"]) == 6
            for mode in modes.values()),
        "unknown_branch_skipped": all(any(item["function"] == "unknown_branch"
                                          for item in mode["skipped_functions"])
                                      for mode in modes.values()),
        "wheel_excludes_test_baseline": True,
        "wheel_metadata_and_license": True,
        "isolated_installed_import": True,
        "root_documents_absent": True,
        "sdist_documents_match": True,
    }
    receipt = {
        "project": "ObfuscatedStringRecovery",
        "version": VERSION,
        "author": "dhtfish98",
        "status": "PASS_LOCAL_ONLY" if all(checks.values()) else "FAIL",
        "scope": "ELF64 x86-64 ET_REL straight-line stack-byte reconstruction only",
        "upstream_reference": {
            "repository": "mandiant/flare-floss",
            "commit": "089f3fc7100835459188a61343d8bea3e88b8437",
            "license": "Apache-2.0",
            "relationship": "research reference only; no code copied or bundled",
        },
        "fixture": {
            "source": "tests/fixtures/stack_strings.c",
            "object_sha256": sha(fixture),
            "compile_ms": fixture_compile_ms,
            "native_executed": False,
        },
        "source_manifest_sha256": digest,
        "source_files_sha256": manifest,
        "sdist": {"name": sdist.name, "sha256": sha(sdist), "members": names},
        "wheel": {
            "name": wheel.name, "sha256": sha(wheel),
            "members": wheel_names,
            "metadata": {key: metadata[key] for key in (
                "Name", "Version", "Author", "License-Expression", "License-File"
            )},
        },
        "installed_import": imported,
        "tools": {
            "python": invoke("python-version", [str(python), "--version"], ROOT, env).strip(),
            "clang": invoke("clang-version", ["clang", "--version"], ROOT, env).splitlines()[0],
        },
        "modes": modes,
        "checks": checks,
        "open": [
            "runtime reachability and full x86 or PE coverage",
            "authorized real-sample findings and false-positive rate",
            "CVP eligibility and approval",
        ],
    }
    (BUILD / "validation.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    if receipt["status"] != "PASS_LOCAL_ONLY":
        raise RuntimeError("validation checks failed")
    print(json.dumps({
        "status": receipt["status"],
        "checks": checks,
        "receipt_sha256": sha(BUILD / "validation.json"),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
