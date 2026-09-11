import os
import unittest

from helpers import load_script_module, temporary_repo_copy


class BulletinUnitTests(unittest.TestCase):
    def test_validate_items_accepts_known_ids_and_urls(self):
        with temporary_repo_copy() as repo:
            module = load_script_module("gen_bulletin", repo)
            facts = [
                {
                    "id": "fact-1",
                    "type": "kev",
                    "text": "El CVE CVE-2026-99999 fue agregado al catálogo KEV.",
                    "source_url": "https://example.test/kev",
                }
            ]
            ok, reason = module.validate_items(
                [{"fact_ids": ["fact-1"], "text": "GreenProof registró CVE-2026-99999. https://example.test/kev"}],
                facts,
            )
            self.assertTrue(ok)
            self.assertIsNone(reason)

    def test_validate_items_rejects_banned_language(self):
        with temporary_repo_copy() as repo:
            module = load_script_module("gen_bulletin", repo)
            facts = [
                {"id": "fact-1", "type": "apt", "text": "Se publicó G0007.", "source_url": "https://example.test/apt"}
            ]
            ok, reason = module.validate_items(
                [{"fact_ids": ["fact-1"], "text": "Posiblemente G0007 requiere atención."}],
                facts,
            )
            self.assertFalse(ok)
            self.assertIn("opinión", reason)

    def test_build_facts_skips_already_covered_items(self):
        with temporary_repo_copy() as repo:
            (repo / "data" / "used_kev.json").write_text("{\n  \"used\": []\n}\n", encoding="utf-8")
            (repo / "data" / "used_apts.json").write_text("{\n  \"used\": []\n}\n", encoding="utf-8")
            writeup_dir = repo / "cve-writeups" / "2026"
            writeup_dir.mkdir(parents=True, exist_ok=True)
            (writeup_dir / "CVE-2026-99999.md").write_text("writeup", encoding="utf-8")
            module = load_script_module("gen_bulletin", repo)
            state = load_script_module("gp_state", repo)
            store = state.StateStore()
            try:
                store.record_publication("cve_writeup", "CVE-2026-99999", "cve-writeups/2026/CVE-2026-99999.md", "2026-09-11")
                facts, _ = module.build_facts(
                    module.load_config(),
                    {"covered": {"cve": ["CVE-2026-99999"], "kev": [], "apt": []}},
                    store,
                )
            finally:
                store.close()
            self.assertEqual([fact["type"] for fact in facts], ["stat"])


if __name__ == "__main__":
    unittest.main()
