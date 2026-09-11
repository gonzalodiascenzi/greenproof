#!/usr/bin/env python3
"""
Renderiza templates/writeup_template.md.j2 con los datos que dejó
fetch_cve.py, escribe el archivo en cve-writeups/<año>/<CVE-ID>.md,
y registra el borrador en el storage común.
"""
import json
import os

from gp_common import ROOT, atomic_write_text, load_config, template_env, utc_today
from gp_state import PUBLICATION_TYPES, StateStore


def main():
    config = load_config()
    store = StateStore(config=config)
    try:
        with store.tracked_run("generate_writeup"):
            with open(os.path.join(ROOT, ".greenproof_cve_data.json"), encoding="utf-8") as f:
                data = json.load(f)

            data["generated_at"] = utc_today()
            rendered = template_env().get_template("writeup_template.md.j2").render(**data)

            year = data["cve_id"].split("-")[1]
            out_dir = os.path.join(ROOT, config["writeups_dir"], year)
            os.makedirs(out_dir, exist_ok=True)
            out_path = os.path.join(out_dir, f"{data['cve_id']}.md")

            atomic_write_text(out_path, rendered)
            print(f"Escrito: {out_path}")

            store.record_publication(
                publication_type=PUBLICATION_TYPES["cve"],
                natural_id=data["cve_id"],
                path=os.path.relpath(out_path, ROOT),
                generated_at=data["generated_at"],
            )
            print(f"Actualizado: {os.path.join(ROOT, config['state_file'])}")
    finally:
        store.close()


if __name__ == "__main__":
    main()
