"""End-to-end checks on self-compiled ELF objects, never native execution."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from obfuscated_string_recovery import BudgetExceeded, InputRejected, Limits, scan_bytes, scan_path
from weak_baseline import visible_literals


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def compile_object(source: Path, output: Path) -> None:
    subprocess.run(
        [
            "clang", "-target", "x86_64-unknown-linux-gnu", "-O0",
            "-fno-stack-protector", "-fno-omit-frame-pointer", "-c",
            str(source), "-o", str(output),
        ],
        check=True, capture_output=True, text=True, timeout=30,
    )


class ScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        build = ROOT / "Build"
        build.mkdir(exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(prefix="scanner-tests-", dir=build)
        cls.object = Path(cls.temp.name) / "stack_strings.o"
        cls.relocated = Path(cls.temp.name) / "text_relocation.o"
        compile_object(FIXTURES / "stack_strings.c", cls.object)
        compile_object(FIXTURES / "text_relocation.c", cls.relocated)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def test_stack_values_and_exact_provenance(self) -> None:
        raw = self.object.read_bytes()
        result = scan_path(self.object)
        self.assertEqual(result["status"], "PASS_STATIC_ONLY")
        self.assertEqual({row["value"] for row in result["findings"]}, {"HELLO", "WORLD"})
        by_value = {row["value"]: row for row in result["findings"]}
        self.assertEqual(by_value["HELLO"]["classification"], "plain_stack")
        self.assertEqual(by_value["WORLD"]["classification"], "decoded")
        self.assertEqual(by_value["HELLO"]["function"], "stack_plain")
        self.assertEqual(by_value["WORLD"]["function"], "stack_encoded")
        self.assertEqual(by_value["HELLO"]["stack_start"], -8)
        self.assertEqual(by_value["WORLD"]["stack_start"], -8)
        initial_bytes = {
            value: bytes(raw[row["initial_file_offset"] + 3]
                         for row in finding["byte_provenance"])
            for value, finding in by_value.items()
        }
        self.assertEqual(initial_bytes["HELLO"], b"HELLO\x00")
        self.assertEqual(initial_bytes["WORLD"], bytes(letter ^ 0x21 for letter in b"WORLD\x00"))
        for value, finding in by_value.items():
            self.assertEqual(len(finding["byte_provenance"]), len(value) + 1)
            for index, entry in enumerate(finding["byte_provenance"]):
                first = entry["initial_file_offset"]
                last = entry["last_write_file_offset"]
                self.assertEqual(raw[first:first + 2], b"\xc6\x45")
                self.assertGreaterEqual(last, first)
                self.assertEqual(entry["stack_offset"], -8 + index)
                if value == "WORLD":
                    self.assertEqual(raw[last:last + 2], b"\x88\x45")
                for changed in entry["transform_file_offsets"]:
                    self.assertEqual(raw[changed:changed + 2], b"\x83\xf0")
            if value == "WORLD":
                self.assertEqual(len(finding["transform_file_offsets"]), 6)
        self.assertIn("unknown_branch", {row["function"] for row in result["skipped_functions"]})
        self.assertNotIn("SECRET", {row["value"] for row in result["findings"]})

    def test_baseline_misses_stack_strings_but_sees_literal(self) -> None:
        literals = visible_literals(self.object.read_bytes())
        self.assertIn("SAFE_NOTICE", literals)
        self.assertNotIn("WORLD", literals)
        self.assertNotIn("HELLO", literals)
        self.assertEqual({row["value"] for row in scan_path(self.object)["findings"]},
                         {"HELLO", "WORLD"})

    def test_no_native_execution_of_unknown_input(self) -> None:
        raw = self.object.read_bytes()
        with patch("subprocess.run", side_effect=AssertionError("native subprocess called")), \
             patch("os.system", side_effect=AssertionError("native shell called")):
            result = scan_bytes(raw)
        self.assertEqual(result["status"], "PASS_STATIC_ONLY")
        self.assertEqual(result["counts"]["findings"], 2)

    def test_relocation_and_malformed_data_rejected(self) -> None:
        with self.assertRaises(InputRejected):
            scan_path(self.relocated)
        for data in (b"", b"not an ELF", self.object.read_bytes()[:50]):
            with self.subTest(data=data[:12]), self.assertRaises(InputRejected):
                scan_bytes(data)
        raw = self.object.read_bytes()
        wrong_machine = bytearray(raw)
        wrong_machine[18:20] = (183).to_bytes(2, "little")
        with self.assertRaises(InputRejected):
            scan_bytes(bytes(wrong_machine))
        excessive_sections = bytearray(raw)
        excessive_sections[60:62] = (255).to_bytes(2, "little")
        with self.assertRaises(InputRejected):
            scan_bytes(bytes(excessive_sections))
        outside_section_table = bytearray(raw)
        outside_section_table[40:48] = (len(raw) + 1).to_bytes(8, "little")
        with self.assertRaises(InputRejected):
            scan_bytes(bytes(outside_section_table))

    def test_deterministic_and_wall_budgets(self) -> None:
        raw = self.object.read_bytes()
        with self.assertRaises(BudgetExceeded):
            scan_bytes(raw, Limits(max_instructions=10))
        with patch("obfuscated_string_recovery.scanner.time.monotonic",
                   side_effect=[0.0, 1.0]):
            with self.assertRaises(BudgetExceeded):
                scan_bytes(raw, Limits(max_wall_ms=1))
        with self.assertRaises(InputRejected):
            scan_bytes(raw, Limits(max_file_bytes=len(raw) - 1))


if __name__ == "__main__":
    unittest.main()
