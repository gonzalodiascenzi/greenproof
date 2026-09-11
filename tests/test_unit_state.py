import sqlite3
import unittest

from helpers import load_script_module, temporary_repo_copy


class StateStoreTests(unittest.TestCase):
    def test_migrates_legacy_json_and_exports_consistently(self):
        with temporary_repo_copy() as repo:
            (repo / "data" / "used_cves.json").write_text(
                '{"used": [{"id": "CVE-2026-99999", "drafted_at": "2026-09-11", "path": "cve-writeups/2026/CVE-2026-99999.md"}]}\n',
                encoding="utf-8",
            )
            module = load_script_module("gp_state", repo)
            store = module.StateStore()
            try:
                pubs = store.list_publications(module.PUBLICATION_TYPES["cve"])
                self.assertEqual(pubs[0]["natural_id"], "CVE-2026-99999")
            finally:
                store.close()
            exported = (repo / "data" / "used_cves.json").read_text(encoding="utf-8")
            self.assertIn("CVE-2026-99999", exported)

    def test_record_publication_is_idempotent(self):
        with temporary_repo_copy() as repo:
            module = load_script_module("gp_state", repo)
            store = module.StateStore()
            try:
                store.record_publication("cve_writeup", "CVE-2026-99999", "a.md", "2026-09-11")
                store.record_publication("cve_writeup", "CVE-2026-99999", "a.md", "2026-09-11")
                rows = store.conn.execute(
                    "SELECT COUNT(*) FROM publications WHERE publication_type = 'cve_writeup' AND natural_id = 'CVE-2026-99999'"
                ).fetchone()[0]
            finally:
                store.close()
            self.assertEqual(rows, 1)

    def test_workflow_runs_are_tracked(self):
        with temporary_repo_copy() as repo:
            module = load_script_module("gp_state", repo)
            store = module.StateStore()
            try:
                with store.tracked_run("test-script"):
                    pass
                row = store.conn.execute("SELECT script_name, status FROM workflow_runs ORDER BY id DESC LIMIT 1").fetchone()
            finally:
                store.close()
            self.assertEqual(tuple(row), ("test-script", "success"))


if __name__ == "__main__":
    unittest.main()
