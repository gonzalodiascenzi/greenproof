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
import urllib.request
import urllib.error
from datetime import datetime, timezone

import yaml
from jinja2 import Environment, FileSystemLoader

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def load_config():
    with open(os.path.join(ROOT, "config.yml"), encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def fetch_kev():
    headers = {"User-Agent": "greenproof/0.1 (+https://github.com/)"}
    req = urllib.request.Request(KEV_URL, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main():
    config = load_config()
    kev_state = load_json(os.path.join(ROOT, config["kev_state_file"]), {"used": []})
    cve_state = load_json(os.path.join(ROOT, config["state_file"]), {"used": []})

    kev_used_ids = {u["cve_id"] for u in kev_state["used"]}
    cve_covered_ids = {u["id"] for u in cve_state["used"]}

    try:
        catalog = fetch_kev()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        print(f"No se pudo traer el catálogo KEV de CISA: {e}", file=sys.stderr)
        sys.exit(1)

    entries = catalog.get("vulnerabilities", [])
    # Los más nuevos primero: dateAdded es YYYY-MM-DD, ordena bien como string.
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

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    env = Environment(
        loader=FileSystemLoader(os.path.join(ROOT, "templates")),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("kev_alert_template.md.j2")
    rendered = template.render(
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
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(rendered)
    print(f"Escrito: {out_path}")

    kev_state["used"].append(
        {
            "cve_id": item["cveID"],
            "drafted_at": generated_at,
            "path": os.path.relpath(out_path, ROOT),
        }
    )
    kev_state_path = os.path.join(ROOT, config["kev_state_file"])
    with open(kev_state_path, "w", encoding="utf-8") as f:
        json.dump(kev_state, f, ensure_ascii=False, indent=2)

    print(f"OK — alerta KEV para {item['cveID']} generada.")
    sys.exit(0)


if __name__ == "__main__":
    main()

