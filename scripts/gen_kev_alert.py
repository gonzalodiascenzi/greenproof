#!/usr/bin/env python3
"""
Trae el catálogo público KEV (Known Exploited Vulnerabilities) de CISA y
genera una alerta corta para el próximo CVE con explotación confirmada que
todavía no cubrimos (ni como writeup completo, ni como alerta KEV previa).

100% factual: todos los campos vienen tal cual del catálogo de CISA, no hay
interpretación agregada por el script.

Exit codes:
  0 = generó una alerta nueva (hay que commitear)
  3 = no hay ningún CVE nuevo en el catálogo KEV que no tengamos ya cubierto
  1 = error real (red, parseo, etc.)
"""
import json
import os
import sys
import urllib.error
import urllib.request

from gp_common import ROOT, atomic_write_text, load_config, read_json_file, template_env, utc_today
from gp_state import PUBLICATION_TYPES, StateStore

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def load_json(path, default):
    return read_json_file(path, default)


def fetch_kev():
    headers = {"User-Agent": "greenproof/0.1 (+https://github.com/)"}
    req = urllib.request.Request(KEV_URL, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main():
    config = load_config()
    store = StateStore(config=config)
    try:
        with store.tracked_run("gen_kev_alert"):
            kev_used_ids = {u["natural_id"] for u in store.list_publications(PUBLICATION_TYPES["kev"])}
            cve_covered_ids = {u["natural_id"] for u in store.list_publications(PUBLICATION_TYPES["cve"])}

            try:
                catalog = fetch_kev()
            except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
                print(f"No se pudo traer el catálogo KEV de CISA: {e}", file=sys.stderr)
                sys.exit(1)

            entries = catalog.get("vulnerabilities", [])
            entries.sort(key=lambda e: e.get("dateAdded", ""), reverse=True)

            item = next(
                (
                    e
                    for e in entries
                    if e["cveID"] not in kev_used_ids and e["cveID"] not in cve_covered_ids
                ),
                None,
            )
            if item is None:
                print("No hay ningún CVE nuevo en el catálogo KEV que no tengamos ya cubierto.")
                sys.exit(3)

            generated_at = utc_today()
            rendered = template_env().get_template("kev_alert_template.md.j2").render(
                cve_id=item["cveID"],
                vulnerability_name=item.get("vulnerabilityName"),
                vendor_project=item.get("vendorProject"),
                product=item.get("product"),
                date_added=item.get("dateAdded"),
                due_date=item.get("dueDate"),
                known_ransomware_use=item.get("knownRansomwareCampaignUse", "Unknown"),
                short_description=item.get("shortDescription"),
                required_action=item.get("requiredAction"),
                generated_at=generated_at,
            )

            out_dir = os.path.join(ROOT, config["kev_dir"])
            os.makedirs(out_dir, exist_ok=True)
            out_path = os.path.join(out_dir, f"{item['cveID']}.md")
            atomic_write_text(out_path, rendered)
            print(f"Escrito: {out_path}")

            store.record_publication(
                publication_type=PUBLICATION_TYPES["kev"],
                natural_id=item["cveID"],
                path=os.path.relpath(out_path, ROOT),
                generated_at=generated_at,
            )

            print(f"OK — alerta KEV para {item['cveID']} generada.")
    finally:
        store.close()


if __name__ == "__main__":
    main()
