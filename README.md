# GreenProof — MVP (track ciberseguridad)

Genera borradores reales de writeups de CVEs conocidos (datos de la NVD),
los abre como Pull Request, y cuando vos los revisás y mergeás, ese merge
queda en tu calendario de contribuciones con la fecha real de hoy. Nada de
fechas manuales al pasado, nada de commits vacíos.

## Cómo funciona (resumen)

1. `.github/workflows/greenproof.yml` corre en el cron que definas (por
   defecto: lunes/miércoles/viernes).
2. `scripts/fetch_cve.py` toma el próximo CVE de `data/notable_cves.json`
   que todavía no se usó, y trae sus datos reales desde la
   [API de la NVD](https://nvd.nist.gov/developers/vulnerabilities).
3. `scripts/generate_writeup.py` renderiza `templates/writeup_template.md.j2`
   con esos datos y lo guarda en `cve-writeups/<año>/<CVE-ID>.md`.
4. El workflow commitea eso en una rama y abre un PR.
5. **Vos completás las secciones `TODO`** (explicación en criollo, contexto
   real / actor conocido si aplica, IOCs o mitigación) y mergeás. El merge
   es el commit real que cuenta en tu perfil.

Si un borrador no te convence, cerrá el PR sin mergear — ya quedó marcado
como "usado" así que no se vuelve a proponer solo.

## Setup

1. **Creá un repo en GitHub** (puede ser el que ya tenés desde 2021, o uno
   nuevo dedicado a esto — cualquiera de los dos suma al mismo calendario)
   y subí este proyecto tal cual está.

2. **Revisá `config.yml`**:
   ```yaml
   commits_per_week: 3   # tiene que coincidir con los días de cron abajo
   ```

3. **Ajustá el cron si querés otra cadencia**, en
   `.github/workflows/greenproof.yml`:
   ```yaml
   - cron: "0 13 * * 1,3,5"   # min hora díaDelMes mes díaDeLaSemana (UTC)
   ```
   Días de la semana: `0`=domingo … `6`=sábado. El ejemplo (`1,3,5`) es
   lunes/miércoles/viernes a las 13:00 UTC (10:00 en Argentina). Si querés
   5 por semana, usá `1,2,3,4,5` y actualizá `commits_per_week: 5`.

4. **(Opcional) Pedí una API key gratuita de la NVD** en
   <https://nvd.nist.gov/developers/request-an-api-key> — sin key el rate
   limit es más bajo (igual alcanza para una corrida cada tanto), con key
   es más alto y más estable. Si la conseguís, agregala como secret del
   repo: **Settings → Secrets and variables → Actions → New repository
   secret**, nombre `NVD_API_KEY`.

5. **Habilitá Pull Requests desde Actions**: en **Settings → Actions →
   General → Workflow permissions**, marcá "Allow GitHub Actions to
   create and approve pull requests". Sin esto, `gh pr create` falla con
   un error de permisos.

6. **Probalo manualmente** antes de dejarlo correr solo: en la pestaña
   **Actions** del repo, elegí el workflow "GreenProof" y usá **Run
   workflow** (está habilitado por `workflow_dispatch`). Revisá el PR que
   se abre.

## Probar el pipeline sin tocar GitHub

```bash
pip install -r requirements.txt
python tests/test_pipeline.py
```

Esto corre `fetch_cve.py` / `generate_writeup.py` contra una respuesta real
de la NVD grabada como fixture (no llama a la red — útil si estás en una
red restringida) y valida que el writeup se genera bien. Para probar el
fetch en vivo contra la NVD de verdad, simplemente corré:

```bash
python scripts/fetch_cve.py && python scripts/generate_writeup.py
```

en una máquina con salida a internet.

## Estructura

```
greenproof-mvp/
├─ config.yml                       # track, cadencia, paths
├─ data/
│  ├─ notable_cves.json             # cola curada de CVEs conocidos (editable)
│  └─ used_cves.json                # estado — qué CVEs ya se usaron
├─ templates/writeup_template.md.j2 # plantilla del writeup
├─ scripts/
│  ├─ fetch_cve.py                  # elige CVE + trae datos reales de la NVD
│  └─ generate_writeup.py           # renderiza y guarda el .md
├─ cve-writeups/<año>/<CVE-ID>.md   # los writeups terminan acá
├─ tests/                           # test offline con fixture real
└─ .github/workflows/greenproof.yml # el scheduler
```

## Qué NO hace (a propósito)

- No pone fechas de commit manuales ni backdatea nada — la fecha del
  commit siempre es la real, del momento en que mergeás.
- No auto-mergea: cada writeup pasa por vos antes de contar.
- No genera contenido "de análisis propio" — el texto autogenerado es
  siempre la descripción oficial de la NVD, citada como tal; lo que vos
  escribís en las secciones `TODO` es lo único que se presenta como tuyo.

## Ideas para las próximas fases (no incluidas en este MVP)

- Track "dev general" (TIL / katas) en paralelo al de cybersec.
- Selección de CVEs "frescos" desde el feed de publicaciones recientes de
  la NVD, además de la cola curada, para writeups de incidentes nuevos.
- Un resumen tipo "boletín" (diario/semanal) armado a partir de los
  writeups ya mergeados — la base para el portal de noticias de vulns/IOCs
  que mencionaste como visión a más largo plazo.
- Dashboard simple (racha, cobertura por año/vendor) usando `used_cves.json`
  como fuente de datos.

## Nota sobre el testing en este entorno

Los scripts se probaron con una respuesta real de la NVD grabada como
fixture (`tests/fixture_cve_2021_44228.json`), porque esta sesión no tiene
salida de red hacia `nvd.nist.gov` (política de la organización). Los
runners de GitHub Actions sí tienen salida a internet normal, así que el
fetch en vivo debería funcionar ahí sin cambios — de todas formas, corré
el workflow manualmente (paso 6 del setup) antes de confiar en el cron.

