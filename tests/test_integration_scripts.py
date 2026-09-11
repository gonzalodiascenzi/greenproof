import json
import os
import unittest
from unittest.mock import patch

from helpers import load_fixture, load_script_module, temporary_repo_copy


class IntegrationScriptTests(unittest.TestCase):
    def test_fetch_cve_writes_current_files(self):
        with temporary_repo_copy() as repo:
            module = load_script_module("fetch_cve", repo)
            with patch.object(module, "fetch_from_nvd", return_value=load_fixture("nvd_cve_response.json")):
                module.main()
            data = json.loads((repo / ".greenproof_cve_data.json").read_text(encoding="utf-8"))
            self.assertEqual(data["cve_id"], "CVE-2014-0160")
            self.assertEqual((repo / ".greenproof_current_cve.txt").read_text(encoding="utf-8"), "CVE-2014-0160")

    def test_generate_writeup_renders_markdown_and_updates_state(self):
        with temporary_repo_copy() as repo:
            module = load_script_module("generate_writeup", repo)
            payload = {
                "cve_id": "CVE-2026-99999",
                "known_as": "Alias",
                "note": "Curated note",
                "published": "2026-09-10",
                "description": "Sample description",
                "cvss_score": 9.8,
                "cvss_severity": "CRITICAL",
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "affected_list": "acme widget",
                "references": ["https://example.test/advisory"],
            }
            (repo / ".greenproof_cve_data.json").write_text(json.dumps(payload), encoding="utf-8")
            module.main()
            rendered = (repo / "cve-writeups" / "2026" / "CVE-2026-99999.md").read_text(encoding="utf-8")
            self.assertIn("# Alias — CVE-2026-99999", rendered)
            self.assertIn("Sample description", rendered)
            self.assertIn("CVE-2026-99999", (repo / "data" / "used_cves.json").read_text(encoding="utf-8"))

    def test_gen_apt_profile_uses_queue_and_updates_state(self):
        with temporary_repo_copy() as repo:
            module = load_script_module("gen_apt_profile", repo)
            module.main()
            rendered = (repo / "threat-intel" / "apt" / "G0007.md").read_text(encoding="utf-8")
            self.assertIn("APT28", rendered)
            self.assertIn("G0007", (repo / "data" / "used_apts.json").read_text(encoding="utf-8"))

    def test_gen_kev_alert_uses_fixture_catalog(self):
        with temporary_repo_copy() as repo:
            module = load_script_module("gen_kev_alert", repo)
            with patch.object(module, "fetch_kev", return_value=load_fixture("kev_catalog.json")):
                module.main()
            rendered = (repo / "threat-intel" / "kev" / "CVE-2026-99999.md").read_text(encoding="utf-8")
            self.assertIn("Explotación confirmada", rendered)
            self.assertIn("CVE-2026-99999", (repo / "data" / "used_kev.json").read_text(encoding="utf-8"))

    def test_enrich_cve_appends_once_and_tracks_idempotence(self):
        with temporary_repo_copy() as repo:
            writeup_path = repo / "cve-writeups" / "2026" / "CVE-2026-99999.md"
            writeup_path.parent.mkdir(parents=True, exist_ok=True)
            writeup_path.write_text("# CVE-2026-99999\n", encoding="utf-8")
            state_path = repo / "data" / "used_cves.json"
            state_path.write_text(
                '{"used": [{"id": "CVE-2026-99999", "drafted_at": "2026-09-10", "path": "cve-writeups/2026/CVE-2026-99999.md"}]}\n',
                encoding="utf-8",
            )
            module = load_script_module("enrich_cve", repo)
            with patch.object(module, "fetch_kev", return_value=load_fixture("kev_catalog.json")):
                with self.assertRaises(SystemExit) as first:
                    module.main()
                self.assertEqual(first.exception.code, 0)
                with self.assertRaises(SystemExit) as second:
                    module.main()
                self.assertEqual(second.exception.code, 3)
            content = writeup_path.read_text(encoding="utf-8")
            self.assertEqual(content.count(module.MARKER), 1)

    def test_gen_bulletin_uses_validated_model_output_and_updates_cursor(self):
        with temporary_repo_copy() as repo:
            writeup_path = repo / "cve-writeups" / "2026" / "CVE-2026-99999.md"
            writeup_path.parent.mkdir(parents=True, exist_ok=True)
            writeup_path.write_text("writeup", encoding="utf-8")
            (repo / "data" / "used_cves.json").write_text(
                '{"used": [{"id": "CVE-2026-99999", "drafted_at": "2026-09-11", "path": "cve-writeups/2026/CVE-2026-99999.md"}]}\n',
                encoding="utf-8",
            )
            bulletin_dir = repo / "threat-intel" / "bulletins"
            for existing in bulletin_dir.glob("*.md"):
                existing.unlink()
            module = load_script_module("gen_bulletin", repo)
            os.environ["ANTHROPIC_API_KEY"] = "test-key"
            with patch.object(module, "call_anthropic", return_value=load_fixture("anthropic_valid_response.json")):
                with self.assertRaises(SystemExit) as exit_ctx:
                    module.main()
                self.assertEqual(exit_ctx.exception.code, 0)
            bulletins = list((repo / "threat-intel" / "bulletins").glob("*.md"))
            self.assertEqual(len(bulletins), 1)
            cursor = json.loads((repo / "data" / "bulletin_state.json").read_text(encoding="utf-8"))
            self.assertIn("CVE-2026-99999", cursor["covered"]["cve"])


if __name__ == "__main__":
    unittest.main()
