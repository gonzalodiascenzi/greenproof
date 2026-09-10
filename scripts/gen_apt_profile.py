#!/usr/bin/env python3
"""
Genera el perfil de un actor (APT) a partir de la cola curada en
data/known_apts.json, con datos citados de MITRE ATT&CK. No llama a ninguna
red — la cola ya trae los campos que necesita el template.

Exit codes:
  0 = generó un perfil nuevo (hay que commitear)
  3 = no queda ningún grupo sin usar en la cola (no hacer nada, no es error)
  1 = error real
"""
import json
import os
import sys
from datetime import datetime, timezone

import yaml
from jinja2 import Environment, FileSystemLoader

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_config():
    with open(os.path.join(ROOT, "config.yml"), encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main():
    config = load_config()
    queue = load_json(os.path.join(ROOT, config["apt_queue_file"]), [])
    state = load_json(os.path.join(ROOT, config["apt_state_file"]), {"used": []})
    used_ids = {u["attack_id"] for u in state["used"]}

    item = next((g for g in queue if g["attack_id"] not in used_ids), None)
    if item is None:
        print("No quedan grupos sin usar en data/known_apts.json.")
        sys.exit(3)

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    env = Environment(
        loader=FileSystemLoader(os.path.join(ROOT, "templates")),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("apt_profile_template.md.j2")
    rendered = template.render(generated_at=generated_at, **item)

    out_dir = os.path.join(ROOT, config["apt_dir"])
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{item['attack_id']}.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(rendered)
    print(f"Escrito: {out_path}")

    state["used"].append(
        {
            "attack_id": item["attack_id"],
            "name": item["name"],
            "drafted_at": generated_at,
            "path": os.path.relpath(out_path, ROOT),
        }
    )
    state_path = os.path.join(ROOT, config["apt_state_file"])
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

    print(f"OK — perfil de {item['name']} ({item['attack_id']}) generado.")
    sys.exit(0)


if __name__ == "__main__":
    main()

