#!/usr/bin/env python3
"""
Boletín de inteligencia — "deep research" acotado.

Diseño híbrido, pedido explícitamente así para que el bot sea un reportero y
no un analista que opina:

1. Esta parte (Python puro, sin IA) junta HECHOS 100% determinísticos a
   partir de lo que los otros scripts ya trajeron de fuentes reales y ya
   está commiteado en `main` — CVEs con writeup mergeado, alertas KEV,
   perfiles de actor. Cada hecho es una oración armada por f-string a partir
   de campos ya reales, con su URL fuente real. Ningún hecho nuevo se
   investiga acá; solo se reusa lo que ya se validó en corridas anteriores.
2. Un modelo de Anthropic redacta, a partir de ESA lista de hechos (nunca
   navegando ni inventando por su cuenta), un ítem periodístico corto por
   hecho — en JSON estructurado, no en markdown libre.
3. Antes de escribir o commitear nada, se valida la respuesta: todo
   identificador (CVE, ID de MITRE) o URL que aparezca en el texto generado
   tiene que existir literalmente en los hechos que le dimos; toda oración
   tiene que citar al menos un hecho real; no puede haber palabras de
   opinión/especulación. Si algo de esto falla, NO se commitea nada — el
   validador rechaza, no "arregla".

Solo se reportan hechos nuevos desde el último boletín (data/bulletin_state.json
trackea qué ids ya se cubrieron) — así el boletín crece con cada ciclo real
sin repetirse nunca a sí mismo.

Exit codes:
  0 = generó un boletín nuevo, validado (hay que commitear)
  3 = no hay hechos nuevos, o falta ANTHROPIC_API_KEY (no es un error)
  1 = error real: falla de red/API, o la respuesta del modelo no pasó el
      validador (hubo material nuevo, se intentó, no se pudo confiar en el
      resultado — visible en el log para que lo revises)
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

import yaml
from jinja2 import Environment, FileSystemLoader

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

# Términos que delatan opinión, recomendación o especulación propia del bot.
# Si aparecen en el texto generado, se rechaza el boletín entero — un
# reportero cita hechos, no opina ni especula por vos.
BANNED_WORDS = [
    "recomendamos",
    "recomendable",
    "deberías",
    "debería",
    "debieras",
    "es crítico que",
    "es fundamental que",
    "posiblemente",
    "probablemente",
    "sospechamos",
    "sospecha",
    "atribuimos",
    "atribución",
    "creemos que",
    "consideramos que",
    "alarmante",
    "preocupante",
    "urgimos",
    "instamos",
    "en mi opinión",
]

SYSTEM_PROMPT = """Sos un reportero de ciberseguridad para un boletín automático. Se te da una lista de HECHOS verificados, cada uno con "id", "type", "text" y "source_url" — todos ya confirmados contra una fuente pública real (NVD, CISA KEV, MITRE ATT&CK) o contra el propio historial del proyecto.

Tu única tarea es redactar, para algunos o todos esos hechos, un ítem periodístico breve en español que resuma ESE hecho puntual — sin agregar ningún dato, cifra, nombre, identificador o URL que no esté literalmente en el "text" del hecho citado. No opines, no recomiendes, no especules, no atribuyas causalidad ni intención que la fuente no afirme. No hagas relleno genérico si un hecho no da para más de una oración corta.

Respondé ÚNICAMENTE con un objeto JSON, sin texto antes ni después, sin backticks ni bloques de código, con esta forma exacta:

{"items": [{"fact_ids": ["fact-1"], "text": "oración que resume fact-1"}]}

Reglas:
- "fact_ids" es una lista no vacía de ids que existen en la lista de hechos que te dieron.
- Un ítem puede combinar 2 hechos relacionados si tiene sentido (por ejemplo, el mismo vendor), citando ambos ids.
- No incluyas ningún hecho dos veces en ítems distintos.
- Si ningún hecho tiene contenido suficiente para una oración con sentido, devolvé {"items": []}.
"""


def load_config():
    with open(os.path.join(ROOT, "config.yml"), encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def nvd_url(cve_id):
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def mitre_url(attack_id):
    return f"https://attack.mitre.org/groups/{attack_id}"


def build_facts(config, cursor):
    """
    Devuelve (facts_for_model, fact_meta) donde:
    - facts_for_model: lista de {id, type, text, source_url} — esto es lo
      único que ve el modelo.
    - fact_meta: dict fact_id -> {"kind": "cve"|"kev"|"apt"|"stat", "natural_id": str|None}
      para poder actualizar el cursor después, sin que el modelo lo maneje.
    """
    facts = []
    meta = {}
    counter = [0]

    def add_fact(kind, text, source_url, natural_id=None, label=""):
        counter[0] += 1
        fid = f"fact-{counter[0]}"
        facts.append({"id": fid, "type": kind, "text": text, "source_url": source_url})
        meta[fid] = {"kind": kind, "natural_id": natural_id, "label": label}
        return fid

    covered = cursor.get("covered", {"cve": [], "kev": [], "apt": []})

    cve_state = load_json(os.path.join(ROOT, config["state_file"]), {"used": []})
    for entry in cve_state.get("used", []):
        cid = entry.get("id")
        if not cid or cid in covered.get("cve", []):
            continue
        path = os.path.join(ROOT, entry.get("path", ""))
        if not os.path.exists(path):
            continue  # el PR todavía no mergeó — no cuenta como hecho real todavía
        text = (
            f"Se mergeó un writeup propio para {cid}, publicado en el "
            f"repositorio el {entry.get('drafted_at', 'fecha sin registrar')}."
        )
        add_fact("cve", text, nvd_url(cid), natural_id=cid, label="NVD")

    kev_state = load_json(os.path.join(ROOT, config["kev_state_file"]), {"used": []})
    for entry in kev_state.get("used", []):
        cid = entry.get("cve_id")
        if not cid or cid in covered.get("kev", []):
            continue
        text = (
            f"El CVE {cid} fue agregado al catálogo KEV (Known Exploited "
            f"Vulnerabilities) de CISA — GreenProof lo registró el "
            f"{entry.get('drafted_at', 'fecha sin registrar')}."
        )
        add_fact("kev", text, KEV_CATALOG_URL, natural_id=cid, label="CISA KEV Catalog")

    apt_state = load_json(os.path.join(ROOT, config["apt_state_file"]), {"used": []})
    for entry in apt_state.get("used", []):
        aid = entry.get("attack_id")
        if not aid or aid in covered.get("apt", []):
            continue
        name = entry.get("name", aid)
        text = (
            f"Se publicó el perfil de {name} ({aid}), citando datos públicos "
            f"de MITRE ATT&CK, el {entry.get('drafted_at', 'fecha sin registrar')}."
        )
        add_fact("apt", text, mitre_url(aid), natural_id=aid, label="MITRE ATT&CK")

    # Estadísticas acumuladas — solo números calculados con len(), sin
    # identificadores ni URLs propios, así no pueden confundir el validador.
    total_cve = len([e for e in cve_state.get("used", []) if os.path.exists(os.path.join(ROOT, e.get("path", "")))])
    total_kev = len(kev_state.get("used", []))
    total_apt = len(apt_state.get("used", []))
    stat_text = (
        f"A la fecha, GreenProof lleva {total_cve} writeup(s) de CVE "
        f"mergeado(s), {total_kev} alerta(s) KEV generada(s) y {total_apt} "
        f"perfil(es) de actor publicado(s)."
    )
    add_fact(
        "stat",
        stat_text,
        "https://github.com/gonzalodiascenzi/greenproof/tree/main/threat-intel",
        natural_id=None,
        label="GreenProof — registro del proyecto",
    )

    return facts, meta


def call_anthropic(facts, model, api_key):
    body = {
        "model": model,
        "max_tokens": 1536,
        "temperature": 0,
        "system": SYSTEM_PROMPT,
        "messages": [
            {"role": "user", "content": json.dumps({"facts": facts}, ensure_ascii=False)}
        ],
    }
    req = urllib.request.Request(
        ANTHROPIC_URL,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "x-api-key": api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def extract_model_json(response):
    """Saca el texto de la respuesta de Messages API y lo parsea como JSON,
    tolerando que el modelo lo haya envuelto en un bloque ```json."""
    blocks = response.get("content", [])
    text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return json.loads(text)


def validate_items(items, facts):
    """Devuelve (ok, razón_si_falla). Rechaza, no corrige."""
    if not isinstance(items, list) or not items:
        return False, "El modelo no devolvió ningún ítem."

    facts_by_id = {f["id"]: f for f in facts}
    blob = " ".join(f"{f['text']} {f.get('source_url', '')}" for f in facts)
    allowed_cves = set(re.findall(r"CVE-\d{4}-\d+", blob))
    allowed_groups = set(re.findall(r"\bG\d{4}\b", blob))
    allowed_urls = {u.rstrip(".,;)") for u in re.findall(r"https?://\S+", blob)}

    for item in items:
        if not isinstance(item, dict):
            return False, f"Ítem con forma inesperada: {item!r}"
        fact_ids = item.get("fact_ids") or []
        if not fact_ids:
            return False, f"Ítem sin fact_ids: {item!r}"
        for fid in fact_ids:
            if fid not in facts_by_id:
                return False, f"fact_id inventado (no existe en los hechos): {fid}"

        text = (item.get("text") or "").strip()
        if not text:
            return False, "Ítem con texto vacío."

        lower = text.lower()
        for w in BANNED_WORDS:
            if w in lower:
                return False, f"Palabra de opinión/especulación detectada: '{w}'"

        for cve in re.findall(r"CVE-\d{4}-\d+", text):
            if cve not in allowed_cves:
                return False, f"CVE mencionado que no está en los hechos: {cve}"
        for grp in re.findall(r"\bG\d{4}\b", text):
            if grp not in allowed_groups:
                return False, f"Actor/ID mencionado que no está en los hechos: {grp}"
        for url in re.findall(r"https?://\S+", text):
            if url.rstrip(".,;)") not in allowed_urls:
                return False, f"URL mencionada que no está en los hechos: {url}"

    return True, None


def render_bulletin(env, items, meta, generated_at):
    sources = []  # [{label, url}]
    url_to_num = {}
    rendered_items = []

    for item in items:
        nums = []
        for fid in item["fact_ids"]:
            fmeta = meta[fid]
            url = None
            for f in item["_facts_lookup"]:
                if f["id"] == fid:
                    url = f.get("source_url")
                    break
            if not url:
                continue
            if url not in url_to_num:
                sources.append({"label": fmeta.get("label") or "Fuente", "url": url})
                url_to_num[url] = len(sources)
            n = url_to_num[url]
            if n not in nums:
                nums.append(n)
        suffix = "".join(f" [{n}]" for n in nums)
        rendered_items.append({"text": item["text"], "citation_suffix": suffix})

    template = env.get_template("bulletin_template.md.j2")
    return template.render(
        generated_at=generated_at,
        items=rendered_items,
        sources=sources,
    )


def main():
    config = load_config()
    state_path = os.path.join(ROOT, config["bulletin_state_file"])
    cursor = load_json(state_path, {"last_bulletin_at": None, "covered": {"cve": [], "kev": [], "apt": []}})

    facts, meta = build_facts(config, cursor)
    # Si el único hecho es la estadística acumulada, no hay nada real nuevo.
    real_facts = [f for f in facts if f["type"] != "stat"]
    if not real_facts:
        print("No hay hechos nuevos desde el último boletín — nada que reportar.")
        sys.exit(3)

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print(
            "Falta el secret ANTHROPIC_API_KEY — el boletín queda deshabilitado "
            "hasta que lo configures (ver README, sección 'Boletín de inteligencia')."
        )
        sys.exit(3)

    model = config.get("bulletin_model", "claude-haiku-4-5-20251001")

    try:
        response = call_anthropic(facts, model, api_key)
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = "(no se pudo leer el cuerpo de la respuesta)"
        print(f"No se pudo consultar la API de Anthropic: HTTP {e.code} — {body}", file=sys.stderr)
        sys.exit(1)
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"No se pudo consultar la API de Anthropic: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        parsed = extract_model_json(response)
        items = parsed.get("items", [])
    except (json.JSONDecodeError, AttributeError, KeyError) as e:
        print(f"La respuesta del modelo no es JSON válido: {e}", file=sys.stderr)
        sys.exit(1)

    ok, reason = validate_items(items, facts)
    if not ok:
        print(f"El boletín generado no pasó el validador — no se commitea nada. Motivo: {reason}", file=sys.stderr)
        sys.exit(1)

    for item in items:
        item["_facts_lookup"] = facts

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    env = Environment(
        loader=FileSystemLoader(os.path.join(ROOT, "templates")),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    rendered = render_bulletin(env, items, meta, generated_at)

    out_dir = os.path.join(ROOT, config["bulletin_dir"])
    os.makedirs(out_dir, exist_ok=True)
    base = generated_at
    out_path = os.path.join(out_dir, f"{base}.md")
    suffix = 2
    while os.path.exists(out_path):
        out_path = os.path.join(out_dir, f"{base}-{suffix}.md")
        suffix += 1

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(rendered)
    print(f"Escrito: {out_path}")

    # Actualizar el cursor: TODOS los hechos no-stat que se le mandaron al
    # modelo esta corrida quedan cubiertos, los haya usado o no en su
    # redacción — así ningún hecho queda dando vueltas para siempre pidiendo
    # ser incluido, y el boletín nunca repite un hecho ya considerado.
    covered = cursor.setdefault("covered", {"cve": [], "kev": [], "apt": []})
    for fid, fmeta in meta.items():
        kind = fmeta["kind"]
        nid = fmeta["natural_id"]
        if kind in ("cve", "kev", "apt") and nid and nid not in covered.setdefault(kind, []):
            covered[kind].append(nid)
    cursor["last_bulletin_at"] = generated_at

    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(cursor, f, ensure_ascii=False, indent=2)
    print(f"Actualizado: {state_path}")

    print(f"OK — boletín generado con {len(items)} ítem(s) validado(s).")
    sys.exit(0)


if __name__ == "__main__":
    main()
