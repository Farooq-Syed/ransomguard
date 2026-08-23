import subprocess
import sys
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]


class ExampleScriptTests(unittest.TestCase):
    def test_standalone_ransomware_example_detects_attack(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "simulate_ransomware_example.py",
                "--style",
                "classic",
                "--seed",
                "2026",
                "--n-files",
                "18",
                "--n-windows",
                "5",
            ],
            cwd=PROJECT_DIR,
            text=True,
            capture_output=True,
            check=True,
        )
        output = (completed.stdout or "") + (completed.stderr or "")
        self.assertIn("Detected      : True", output)
        self.assertIn("Attack style  : classic", output)


if __name__ == "__main__":
    unittest.main()
