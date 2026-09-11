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
import os
import sys

from gp_common import ROOT, atomic_write_text, load_config, read_json_file, template_env, utc_today
from gp_state import PUBLICATION_TYPES, StateStore


def load_json(path, default):
    return read_json_file(path, default)


def main():
    config = load_config()
    store = StateStore(config=config)
    try:
        with store.tracked_run("gen_apt_profile"):
            item = store.next_pending_apt()
            if item is None:
                print("No quedan grupos sin usar en data/known_apts.json.")
                sys.exit(3)

            generated_at = utc_today()
            rendered = template_env().get_template("apt_profile_template.md.j2").render(
                generated_at=generated_at,
                **item,
            )

            out_dir = os.path.join(ROOT, config["apt_dir"])
            os.makedirs(out_dir, exist_ok=True)
            out_path = os.path.join(out_dir, f"{item['attack_id']}.md")
            atomic_write_text(out_path, rendered)
            print(f"Escrito: {out_path}")

            store.record_publication(
                publication_type=PUBLICATION_TYPES["apt"],
                natural_id=item["attack_id"],
                path=os.path.relpath(out_path, ROOT),
                generated_at=generated_at,
                metadata={"name": item["name"]},
            )

            print(f"OK — perfil de {item['name']} ({item['attack_id']}) generado.")
    finally:
        store.close()


if __name__ == "__main__":
    main()
