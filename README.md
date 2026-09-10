# GreenProof — MVP (track ciberseguridad)

Genera contenido real de seguridad (writeups de CVEs, alertas de explotación
activa, perfiles de actores) a partir de fuentes públicas — NVD, CISA KEV,
MITRE ATT&CK — y lo commitea con la fecha real de hoy. Nada de fechas
manuales al pasado, nada de commits vacíos, nada de texto inventado: todo lo
que dice GreenProof está citado a una fuente pública verificable.

Hay dos automatizaciones, con dos criterios distintos de cuándo algo "cuenta":

- **Writeup profundo de CVE** (`greenproof.yml`): abre un PR. Vos completás
  tu propio análisis y mergeás — ese merge es el commit real.
- **Señales automáticas** (`greenproof-intel.yml`): alertas KEV, perfiles de
  actor y actualizaciones de writeups ya mergeados. Van directo a `main`,
  sin PR, porque no tienen ninguna interpretación agregada por el bot — son
  cita textual de una fuente pública. Ver más abajo.

## 1. Writeup profundo de CVE (con tu análisis)

1. `scripts/fetch_cve.py` elige el próximo CVE. Primero recorre la cola
   curada en `data/notable_cves.json`; cuando esa cola se agota, busca solo
   un CVE real y reciente (últimos 30 días, CVSS ≥ 7) en el feed de
   publicaciones de la NVD — así la cola nunca se seca sin que tengas que
   agregar CVEs a mano.
2. Trae los datos reales de ese CVE desde la
   [API de la NVD](https://nvd.nist.gov/developers/vulnerabilities).
3. `scripts/generate_writeup.py` renderiza `templates/writeup_template.md.j2`
   y lo guarda en `cve-writeups/<año>/<CVE-ID>.md`.
4. El workflow commitea eso en una rama y abre un PR.
5. **Vos completás las secciones `TODO`** (explicación en criollo, contexto
   real / actor conocido si aplica, IOCs o mitigación) y mergeás. El merge
   es el commit real que cuenta en tu perfil.

Si un borrador no te convence, cerrá el PR sin mergear — ya quedó marcado
como "usado" así que no se vuelve a proponer solo. Y si dejás un PR sin
revisar, el workflow no rompe nada: la próxima corrida detecta que ya hay
una rama pendiente para ese CVE y no hace nada hasta que lo resuelvas.

Corre una vez por día (`commits_per_week: 7` en `config.yml`).

## 2. Señales automáticas (KEV / APT / enrichment)

`greenproof-intel.yml` corre 5 veces por día. En cada corrida intenta, en
este orden, **una sola cosa real** — nunca relleno artificial para completar
un número:

1. **Enrichment**: revisa los writeups que ya mergeaste (`data/used_cves.json`)
   contra el catálogo [KEV de CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
   en vivo. Si alguno de tus CVEs fue agregado a KEV *después* de que lo
   mergeaste, le suma al final una sección real y fechada — no reescribe
   nada de lo que ya está.
2. **Alerta KEV**: si no hay nada para enriquecer, genera una alerta corta
   para un CVE nuevo del catálogo KEV que todavía no cubriste de ninguna
   forma. Se guarda en `threat-intel/kev/<CVE-ID>.md`.
3. **Perfil de actor (APT)**: si tampoco hay eso, toma el próximo grupo sin
   usar de `data/known_apts.json` (23 actores reales y bien documentados —
   APT28, Lazarus, Sandworm, Volt Typhoon, etc.) y genera su perfil citando
   [MITRE ATT&CK](https://attack.mitre.org/) — descripción oficial y
   técnicas asociadas, con ID real (`G00xx` / `T0xxx`) y link a la fuente.
   Se guarda en `threat-intel/apt/<GROUP-ID>.md`.

Si ninguna de las tres tiene material real para esa corrida, el workflow
termina en verde sin commitear nada. Por eso "hasta 6 commits reales por
día" (1 del writeup profundo + hasta 5 de acá) es un techo, no una promesa
fija — algunos días va a haber menos, porque las fuentes públicas no
generan noticia todos los días, y GreenProof no inventa una para rellenar.

Estos tres tipos de contenido van directo a `main` sin pasar por PR porque
no requieren tu criterio para ser correctos: son citas textuales de un
catálogo público (CISA, MITRE), no análisis. Cada uno igual tiene una
sección opcional "Notas propias — TODO" por si más adelante querés sumar
algo tuyo — nunca es obligatoria para que el contenido tenga sentido.

## Setup

1. **Creá un repo en GitHub** y subí este proyecto tal cual está.

2. **(Opcional) Pedí una API key gratuita de la NVD** en
   <https://nvd.nist.gov/developers/request-an-api-key> — sin key el rate
   limit es más bajo (igual alcanza), con key es más alto y más estable.
   Si la conseguís, agregala como secret del repo: **Settings → Secrets
   and variables → Actions → New repository secret**, nombre `NVD_API_KEY`.
   Solo la usa `greenproof.yml`; `greenproof-intel.yml` no la necesita (CISA
   y MITRE son de acceso público, sin key).

3. **Habilitá Pull Requests desde Actions**: en **Settings → Actions →
   General → Workflow permissions**, marcá "Read and write permissions" y
   "Allow GitHub Actions to create and approve pull requests". Sin esto,
   `gh pr create` (en `greenproof.yml`) falla con un error de permisos —
   `greenproof-intel.yml` solo necesita el "Read and write", ya que no abre
   PRs.

4. **Probalo manualmente** antes de dejarlo correr solo: en la pestaña
   **Actions**, elegí cada workflow y usá **Run workflow** (los dos tienen
   `workflow_dispatch`). Revisá el PR que abre uno y el commit directo que
   hace el otro.

5. **Si querés otra cadencia**, ajustá los cron de
   `.github/workflows/greenproof.yml` (`- cron: "0 13 * * *"`, formato
   `min hora díaDelMes mes díaDeLaSemana`, UTC) y de
   `greenproof-intel.yml` (`- cron: "0 11,14,17,20,23 * * *"`, admite varias
   horas separadas por coma). Si cambiás la cadencia del writeup profundo,
   actualizá también `commits_per_week` en `config.yml` para que quede
   documentado.

## Probar el pipeline sin tocar GitHub

```bash
pip install -r requirements.txt
python scripts/fetch_cve.py && python scripts/generate_writeup.py   # writeup profundo
python scripts/gen_kev_alert.py                                      # alerta KEV
python scripts/gen_apt_profile.py                                    # perfil de actor
python scripts/enrich_cve.py                                         # enrichment
```

Todos corren en una máquina con salida a internet (NVD, CISA, o ninguna en
el caso de `gen_apt_profile.py`, que usa el snapshot curado en
`data/known_apts.json`). Cada script termina con código `3` cuando no hay
nada nuevo que hacer — no es un error, es la señal de "hoy no hay novedad
real para esto".

## Estructura

```
greenproof-mvp/
├─ config.yml                            # track, cadencia, paths de cada cola/estado
├─ data/
│  ├─ notable_cves.json                  # cola curada de CVEs conocidos (editable)
│  ├─ used_cves.json                     # estado — CVEs ya mergeados (writeup profundo)
│  ├─ known_apts.json                    # cola curada de actores (MITRE ATT&CK)
│  ├─ used_apts.json                     # estado — perfiles de actor ya generados
│  └─ used_kev.json                      # estado — alertas KEV ya generadas
├─ templates/
│  ├─ writeup_template.md.j2             # plantilla del writeup profundo
│  ├─ kev_alert_template.md.j2           # plantilla de alerta KEV
│  └─ apt_profile_template.md.j2         # plantilla de perfil de actor
├─ scripts/
│  ├─ fetch_cve.py                       # elige CVE (cola + feed NVD en vivo) y trae sus datos
│  ├─ generate_writeup.py                # renderiza y guarda el writeup profundo
│  ├─ gen_kev_alert.py                   # genera una alerta KEV nueva
│  ├─ gen_apt_profile.py                 # genera el próximo perfil de actor
│  └─ enrich_cve.py                      # suma novedades reales de KEV a writeups ya mergeados
├─ cve-writeups/<año>/<CVE-ID>.md        # writeups profundos (vía PR)
├─ threat-intel/
│  ├─ kev/<CVE-ID>.md                    # alertas KEV (commit directo)
│  └─ apt/<GROUP-ID>.md                  # perfiles de actor (commit directo)
└─ .github/workflows/
   ├─ greenproof.yml                     # writeup profundo — abre PR
   └─ greenproof-intel.yml               # señales automáticas — commit directo
```

## Qué NO hace (a propósito)

- No pone fechas de commit manuales ni backdatea nada — la fecha del
  commit siempre es la real, del momento en que se commitea o mergeás.
- El writeup profundo no auto-mergea: pasa por vos antes de contar.
- Las señales automáticas (KEV, APT, enrichment) sí van directo a `main`,
  pero únicamente porque su contenido es 100% cita textual de una fuente
  pública — nunca incluyen una interpretación, atribución o conclusión que
  el bot se haya inventado. Si algún día ese límite se corre (por ejemplo,
  agregar una correlación CVE↔APT que no esté ya documentada por una fuente
  citable), eso tiene que volver a pasar por PR.
- Ningún script rellena con contenido genérico cuando no hay novedad real
  — en ese caso, la corrida no hace ningún commit.

## Ideas para las próximas fases (no incluidas en este MVP)

- Track "dev general" (TIL / katas) en paralelo al de cybersec.
- Cruzar `known_apts.json` con los CVEs ya cubiertos cuando una fuente
  pública documente una explotación real por ese grupo (hoy no se hace
  para no arriesgar una atribución no verificada).
- Un resumen tipo "boletín" (diario/semanal) armado a partir de todo lo ya
  mergeado/commiteado — la base para el portal de noticias de vulns/IOCs
  que mencionaste como visión a más largo plazo.
- Dashboard simple (racha, cobertura por año/vendor/actor) usando los
  archivos de estado como fuente de datos.

## Nota sobre el testing en este entorno

Los scripts se probaron localmente contra respuestas grabadas (fixtures) y
con el dataset público de MITRE ATT&CK descargado una vez para curar
`known_apts.json`, porque esta sesión no tiene salida de red hacia
`nvd.nist.gov` ni `cisa.gov` (política de la organización). Los runners de
GitHub Actions sí tienen salida a internet normal, así que el fetch en vivo
debería funcionar ahí sin cambios — de todas formas, corré cada workflow
manualmente (paso 4 del setup) antes de confiar en el cron.
