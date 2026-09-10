#!/usr/bin/env python3
"""
Revisa los writeups de CVE que ya mergeaste (data/used_cves.json) contra el
catálogo KEV de CISA en vivo. Si alguno fue agregado a KEV *después* de que
lo mergeaste, le suma una sección real y citada al final del archivo —
no reescribe nada de lo que ya está, solo agrega el hecho nuevo.

Hace como mucho UNA actualización por corrida (para que cada commit sea un
cambio real y chico, fácil de revisar) y es idempotente: si el archivo ya
tiene la sección de esta actualización, no la vuelve a agregar.

Exit codes:
  0 = actualizó un writeup (hay que commitear)
  3 = no hay ninguna actualización real pendiente
  1 = error real (red, parseo, etc.)
"""
import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MARKER = "## Actualización — Catálogo KEV de CISA"


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
    cve_state = load_json(os.path.join(ROOT, config["state_file"]), {"used": []})
    if not cve_state["used"]:
        print("Todavía no hay ningún writeup mergeado para revisar.")
        sys.exit(3)

    try:
        catalog = fetch_kev()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        print(f"No se pudo traer el catálogo KEV de CISA: {e}", file=sys.stderr)
        sys.exit(1)

    kev_by_id = {e["cveID"]: e for e in catalog.get("vulnerabilities", [])}

    for entry in cve_state["used"]:
        cve_id = entry["id"]
        if cve_id not in kev_by_id:
            continue
        path = os.path.join(ROOT, entry["path"])
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as f:
            content = f.read()
        if MARKER in content:
            continue  # ya lo anotamos antes

        kev = kev_by_id[cve_id]
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        addition = (
            f"\n{MARKER} ({today})\n\n"
            f"Este CVE fue agregado al catálogo [KEV de CISA]"
            f"(https://www.cisa.gov/known-exploited-vulnerabilities-catalog) "
            f"el **{kev.get('dateAdded')}** — significa que hay explotación "
            f"activa **confirmada**, no teórica.\n\n"
            f"- Uso conocido en ransomware: {kev.get('knownRansomwareCampaignUse', 'Unknown')}\n"
            f"- Acción requerida (CISA): {kev.get('requiredAction')}\n"
            f"- Plazo de remediación (agencias federales EE.UU.): {kev.get('dueDate')}\n"
        )
        with open(path, "a", encoding="utf-8") as f:
            f.write(addition)

        print(f"Actualizado: {path} (agregado a KEV el {kev.get('dateAdded')})")
        sys.exit(0)

    print("Ningún CVE ya mergeado tiene novedades reales en KEV por ahora.")
    sys.exit(3)


if __name__ == "__main__":
    main()

