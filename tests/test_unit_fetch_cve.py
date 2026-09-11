import unittest

from helpers import load_fixture, load_script_module, temporary_repo_copy


class FetchCveUnitTests(unittest.TestCase):
    def test_next_cve_id_skips_used(self):
        with temporary_repo_copy() as repo:
            module = load_script_module("fetch_cve", repo)
            queue = [
                {"id": "CVE-1"},
                {"id": "CVE-2"},
            ]
            self.assertEqual(module.next_cve_id(queue, {"CVE-1"})["id"], "CVE-2")

    def test_normalize_extracts_primary_fields(self):
        with temporary_repo_copy() as repo:
            module = load_script_module("fetch_cve", repo)
            response = load_fixture("nvd_cve_response.json")
            result = module.normalize(response, {"known_as": "Alias", "note": "Curated note"})
            self.assertEqual(result["cve_id"], "CVE-2026-99999")
            self.assertEqual(result["cvss_score"], 9.8)
            self.assertEqual(result["cvss_severity"], "CRITICAL")
            self.assertIn("acme widget", result["affected_list"])
            self.assertEqual(len(result["references"]), 2)

    def test_find_fresh_cve_prefers_highest_score_then_newest(self):
        with temporary_repo_copy() as repo:
            module = load_script_module("fetch_cve", repo)
            payload = load_fixture("nvd_recent_response.json")

            class FakeResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self):
                    import json
                    return json.dumps(payload).encode("utf-8")

            with unittest.mock.patch.object(module.urllib.request, "urlopen", return_value=FakeResponse()):
                item = module.find_fresh_cve({"CVE-2026-77777"})
            self.assertEqual(item["id"], "CVE-2026-99999")


if __name__ == "__main__":
    unittest.main()
