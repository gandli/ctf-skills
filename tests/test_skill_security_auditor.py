import tempfile
import textwrap
import unittest
from pathlib import Path

from scripts.skill_security_auditor import scan_skill


class SkillSecurityAuditorTests(unittest.TestCase):
    def _make_skill(self, skill_md: str, extra_files: dict[str, str] | None = None) -> Path:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        skill_dir = Path(temp_dir.name) / "demo-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text(skill_md, encoding="utf-8")

        for rel_path, content in (extra_files or {}).items():
            file_path = skill_dir / rel_path
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content, encoding="utf-8")

        return skill_dir

    def test_demo_password_in_code_block_is_not_treated_as_secret_leak(self):
        skill_dir = self._make_skill(
            textwrap.dedent(
                """\
                ---
                name: demo-skill
                description: Demo
                license: MIT
                allowed-tools: []
                ---

                Example only.
                """
            ),
            {
                "example.md": textwrap.dedent(
                    """\
                    ```python
                    original_password = "complexPasswordWhichContainsManyCharactersWithRandomSuffixeghjrjg"
                    ```
                    """
                )
            },
        )

        result = scan_skill(skill_dir)

        self.assertEqual(result["verdict"], "PASS")
        self.assertFalse(
            any(finding["severity"] == "CRITICAL" for finding in result["findings"])
        )

    def test_real_github_token_still_triggers_critical_finding(self):
        skill_dir = self._make_skill(
            textwrap.dedent(
                """\
                ---
                name: demo-skill
                description: Demo
                license: MIT
                allowed-tools: []
                ---
                """
            ),
            {
                "secret.md": "ghp_abcdefghijklmnopqrstuvwxyz1234567890\n",
            },
        )

        result = scan_skill(skill_dir)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(
            any("GitHub personal access token" in finding["message"] for finding in result["findings"])
        )

    def test_gdb_parse_and_eval_is_not_flagged_as_python_eval(self):
        skill_dir = self._make_skill(
            textwrap.dedent(
                """\
                ---
                name: demo-skill
                description: Demo
                license: MIT
                allowed-tools: []
                ---
                """
            ),
            {
                "reverse.md": textwrap.dedent(
                    """\
                    ```python
                    rip = int(gdb.parse_and_eval('$rip'))
                    ```
                    """
                )
            },
        )

        result = scan_skill(skill_dir)

        self.assertEqual(result["verdict"], "PASS")
        self.assertFalse(
            any(finding["severity"] == "HIGH" for finding in result["findings"])
        )


if __name__ == "__main__":
    unittest.main()
