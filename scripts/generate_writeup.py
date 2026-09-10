#!/usr/bin/env python3
"""
Renderiza templates/writeup_template.md.j2 con los datos que dejó
fetch_cve.py, escribe el archivo en cve-writeups/<año>/<CVE-ID>.md,
y marca el CVE como usado en data/used_cves.json.
"""
import json
import os
from datetime import datetime, timezone

import yaml
from jinja2 import Environment, FileSystemLoader

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_config():
    with open(os.path.join(ROOT, "config.yml"), encoding="utf-8") as f:
        return yaml.safe_load(f)


def main():
    config = load_config()

    with open(os.path.join(ROOT, ".greenproof_cve_data.json"), encoding="utf-8") as f:
        data = json.load(f)

    data["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    env = Environment(
        loader=FileSystemLoader(os.path.join(ROOT, "templates")),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("writeup_template.md.j2")
    rendered = template.render(**data)

    year = data["cve_id"].split("-")[1]
    out_dir = os.path.join(ROOT, config["writeups_dir"], year)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{data['cve_id']}.md")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(rendered)
    print(f"Escrito: {out_path}")

    state_path = os.path.join(ROOT, config["state_file"])
    with open(state_path, encoding="utf-8") as f:
        state = json.load(f)
    state["used"].append(
        {
            "id": data["cve_id"],
            "drafted_at": data["generated_at"],
            "path": os.path.relpath(out_path, ROOT),
        }
    )
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
    print(f"Actualizado: {state_path}")


if __name__ == "__main__":
    main()

