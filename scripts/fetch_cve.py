#!/usr/bin/env python3
"""
Elige el próximo CVE de la cola que todavía no se usó, trae su información
real desde la API de la NVD, y deja los datos normalizados en
.greenproof_cve_data.json para que generate_writeup.py los consuma.

No inventa nada: si la NVD no tiene un campo, queda como None y el template
lo marca como "sin dato" en vez de rellenarlo con algo falso.
"""
import json
import os
import sys
import time
import urllib.request
import urllib.error
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def load_config():
    with open(os.path.join(ROOT, "config.yml"), encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def next_cve_id(queue, used_ids):
    for item in queue:
        if item["id"] not in used_ids:
            return item
    return None


def fetch_from_nvd(cve_id, api_key=None, retries=3):
    url = f"{NVD_ENDPOINT}?cveId={cve_id}"
    headers = {"User-Agent": "greenproof/0.1 (+https://github.com/)"}
    if api_key:
        headers["apiKey"] = api_key

    last_err = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code == 429:
                time.sleep(6 * (attempt + 1))
                continue
            raise
        except urllib.error.URLError as e:
            last_err = e
            time.sleep(3 * (attempt + 1))
    raise RuntimeError(f"No se pudo consultar la NVD para {cve_id}: {last_err}")


def pick_best_metric(metrics):
    """Prioriza CVSS v3.1 > v3.0 > v2, siempre la métrica 'Primary' si existe."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not entries:
            continue
        primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = primary.get("cvssData", {})
        return {
            "score": data.get("baseScore"),
            "severity": data.get("baseSeverity") or primary.get("baseSeverity"),
            "vector": data.get("vectorString"),
        }
    return {"score": None, "severity": None, "vector": None}


def extract_affected(configurations):
    """Extrae 'vendor product' únicos de los CPE listados, sin duplicar."""
    seen = []
    for config in configurations or []:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) > 4:
                    vendor, product = parts[3], parts[4]
                    label = f"{vendor} {product}".replace("_", " ").strip()
                    if label and label not in seen:
                        seen.append(label)
    return seen[:8]  # tope razonable para no llenar la tabla


def normalize(nvd_response, queue_item):
    vulns = nvd_response.get("vulnerabilities", [])
    if not vulns:
        return None
    cve = vulns[0]["cve"]

    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        None,
    )
    metric = pick_best_metric(cve.get("metrics", {}))
    affected = extract_affected(cve.get("configurations"))
    references = [r["url"] for r in cve.get("references", [])][:6]

    return {
        "cve_id": cve["id"],
        "known_as": queue_item.get("known_as"),
        "note": queue_item.get("note"),
        "published": cve.get("published", "").split("T")[0] or None,
        "description": description,
        "cvss_score": metric["score"],
        "cvss_severity": metric["severity"],
        "cvss_vector": metric["vector"],
        "affected_list": ", ".join(affected) if affected else None,
        "references": references,
    }


def main():
    config = load_config()
    queue = load_json(os.path.join(ROOT, config["queue_file"]), [])
    state = load_json(os.path.join(ROOT, config["state_file"]), {"used": []})
    used_ids = {u["id"] for u in state["used"]}

    item = next_cve_id(queue, used_ids)
    if item is None:
        print("No quedan CVEs sin usar en la cola. Agregá más en data/notable_cves.json.")
        sys.exit(1)

    print(f"Próximo CVE: {item['id']} ({item.get('known_as', 'sin apodo')})")
    nvd_response = fetch_from_nvd(item["id"], api_key=os.environ.get("NVD_API_KEY"))
    data = normalize(nvd_response, item)
    if data is None:
        print(f"La NVD no devolvió datos para {item['id']}.")
        sys.exit(1)

    out_path = os.path.join(ROOT, ".greenproof_cve_data.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    # Para que el workflow sepa qué id está procesando sin volver a parsear JSON.
    with open(os.path.join(ROOT, ".greenproof_current_cve.txt"), "w", encoding="utf-8") as f:
        f.write(data["cve_id"])

    print(f"OK — datos de {data['cve_id']} guardados en {out_path}")


if __name__ == "__main__":
    main()

