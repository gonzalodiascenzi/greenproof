#!/usr/bin/env python3
import json
import os
import sqlite3
from contextlib import contextmanager

from gp_common import ROOT, atomic_write_json, ensure_parent_dir, load_config, read_json_file, utc_today

SCHEMA_VERSION = 1

PUBLICATION_TYPES = {
    "cve": "cve_writeup",
    "kev": "kev_alert",
    "apt": "apt_profile",
}


class StateStore:
    def __init__(self, root=ROOT, config=None):
        self.root = root
        self.config = config or load_config(root)
        rel_db_path = self.config.get("state_db_file", "data/greenproof_state.db")
        self.db_path = os.path.join(root, rel_db_path)
        ensure_parent_dir(self.db_path)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA busy_timeout = 5000")
        self._init_db()
        self.migrate_legacy_state()
        self.sync_curated_inputs()

    def close(self):
        self.conn.close()

    def _init_db(self):
        with self.conn:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS queue_items (
                    queue_type TEXT NOT NULL,
                    item_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    position INTEGER NOT NULL,
                    source_path TEXT,
                    PRIMARY KEY (queue_type, item_id)
                );

                CREATE TABLE IF NOT EXISTS publications (
                    publication_type TEXT NOT NULL,
                    natural_id TEXT NOT NULL,
                    path TEXT NOT NULL,
                    generated_at TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    PRIMARY KEY (publication_type, natural_id)
                );

                CREATE TABLE IF NOT EXISTS coverage_state (
                    flow_name TEXT NOT NULL,
                    item_kind TEXT NOT NULL,
                    natural_id TEXT NOT NULL,
                    covered_at TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    PRIMARY KEY (flow_name, item_kind, natural_id)
                );

                CREATE TABLE IF NOT EXISTS enrichments (
                    enrichment_type TEXT NOT NULL,
                    natural_id TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    applied_at TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    PRIMARY KEY (enrichment_type, natural_id, target_path)
                );

                CREATE TABLE IF NOT EXISTS bulletin_facts (
                    bulletin_path TEXT NOT NULL,
                    fact_key TEXT NOT NULL,
                    fact_kind TEXT NOT NULL,
                    natural_id TEXT,
                    fact_text TEXT NOT NULL,
                    source_url TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (bulletin_path, fact_key)
                );

                CREATE TABLE IF NOT EXISTS workflow_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    script_name TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    status TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS cursor_state (
                    cursor_key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL
                );
                """
            )
            row = self.conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
            if row is None:
                self.conn.execute("INSERT INTO schema_version(version) VALUES (?)", (SCHEMA_VERSION,))
            elif row[0] != SCHEMA_VERSION:
                raise RuntimeError(
                    f"Versión de schema no soportada en {self.db_path}: {row[0]} (esperada {SCHEMA_VERSION})"
                )

    @contextmanager
    def tracked_run(self, script_name, metadata=None):
        run_id = self.start_run(script_name, metadata=metadata)
        try:
            yield run_id
        except SystemExit as exc:
            status = "success" if exc.code in (None, 0, 3) else "error"
            self.finish_run(run_id, status)
            raise
        except Exception:
            self.finish_run(run_id, "error")
            raise
        else:
            self.finish_run(run_id, "success")

    def start_run(self, script_name, metadata=None):
        payload = json.dumps(metadata or {}, ensure_ascii=False)
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO workflow_runs(script_name, started_at, metadata_json) VALUES (?, ?, ?)",
                (script_name, utc_today(), payload),
            )
        return cur.lastrowid

    def finish_run(self, run_id, status):
        with self.conn:
            self.conn.execute(
                "UPDATE workflow_runs SET finished_at = ?, status = ? WHERE id = ?",
                (utc_today(), status, run_id),
            )

    def migrate_legacy_state(self):
        self._migrate_publication_file(
            publication_type=PUBLICATION_TYPES["cve"],
            path_key="state_file",
            id_key="id",
            extra_keys=(),
        )
        self._migrate_publication_file(
            publication_type=PUBLICATION_TYPES["kev"],
            path_key="kev_state_file",
            id_key="cve_id",
            extra_keys=(),
        )
        self._migrate_publication_file(
            publication_type=PUBLICATION_TYPES["apt"],
            path_key="apt_state_file",
            id_key="attack_id",
            extra_keys=("name",),
        )

        bulletin_path = os.path.join(self.root, self.config["bulletin_state_file"])
        legacy_bulletin = read_json_file(
            bulletin_path,
            {"last_bulletin_at": None, "covered": {"cve": [], "kev": [], "apt": []}},
        )
        if legacy_bulletin.get("last_bulletin_at"):
            self.set_cursor("bulletin.last_bulletin_at", legacy_bulletin["last_bulletin_at"])
        for kind in ("cve", "kev", "apt"):
            for natural_id in legacy_bulletin.get("covered", {}).get(kind, []):
                self.record_coverage(
                    flow_name="bulletin",
                    item_kind=kind,
                    natural_id=natural_id,
                    covered_at=legacy_bulletin.get("last_bulletin_at") or utc_today(),
                )

        self.export_legacy_state()

    def _migrate_publication_file(self, publication_type, path_key, id_key, extra_keys):
        path = os.path.join(self.root, self.config[path_key])
        legacy = read_json_file(path, {"used": []})
        for entry in legacy.get("used", []):
            natural_id = entry.get(id_key)
            if not natural_id:
                continue
            metadata = {key: entry.get(key) for key in extra_keys if entry.get(key) is not None}
            self.record_publication(
                publication_type=publication_type,
                natural_id=natural_id,
                path=entry.get("path", ""),
                generated_at=entry.get("drafted_at") or utc_today(),
                metadata=metadata,
                export=False,
            )

    def sync_curated_inputs(self):
        self._sync_queue_file("cve", self.config["queue_file"], "id")
        self._sync_queue_file("apt", self.config["apt_queue_file"], "attack_id")

    def _sync_queue_file(self, queue_type, relative_path, id_key):
        source_path = os.path.join(self.root, relative_path)
        items = read_json_file(source_path, [])
        with self.conn:
            self.conn.execute(
                "DELETE FROM queue_items WHERE queue_type = ? AND source_path = ?",
                (queue_type, relative_path),
            )
            for pos, item in enumerate(items):
                item_id = item.get(id_key)
                if not item_id:
                    continue
                self.conn.execute(
                    "INSERT INTO queue_items(queue_type, item_id, payload_json, position, source_path) VALUES (?, ?, ?, ?, ?)",
                    (queue_type, item_id, json.dumps(item, ensure_ascii=False), pos, relative_path),
                )

    def next_pending_cve(self):
        row = self.conn.execute(
            """
            SELECT item_id, payload_json
            FROM queue_items
            WHERE queue_type = 'cve'
              AND NOT EXISTS (
                SELECT 1 FROM publications
                WHERE publication_type = ? AND natural_id = queue_items.item_id
              )
            ORDER BY position ASC
            LIMIT 1
            """,
            (PUBLICATION_TYPES["cve"],),
        ).fetchone()
        return self._decode_queue_row(row)

    def next_pending_apt(self):
        row = self.conn.execute(
            """
            SELECT item_id, payload_json
            FROM queue_items
            WHERE queue_type = 'apt'
              AND NOT EXISTS (
                SELECT 1 FROM publications
                WHERE publication_type = ? AND natural_id = queue_items.item_id
              )
            ORDER BY position ASC
            LIMIT 1
            """,
            (PUBLICATION_TYPES["apt"],),
        ).fetchone()
        return self._decode_queue_row(row)

    def _decode_queue_row(self, row):
        if row is None:
            return None
        return json.loads(row["payload_json"])

    def has_publication(self, publication_type, natural_id):
        row = self.conn.execute(
            "SELECT 1 FROM publications WHERE publication_type = ? AND natural_id = ?",
            (publication_type, natural_id),
        ).fetchone()
        return row is not None

    def list_publications(self, publication_type):
        rows = self.conn.execute(
            "SELECT natural_id, path, generated_at, metadata_json FROM publications WHERE publication_type = ? ORDER BY generated_at ASC, natural_id ASC",
            (publication_type,),
        ).fetchall()
        results = []
        for row in rows:
            item = {
                "natural_id": row["natural_id"],
                "path": row["path"],
                "generated_at": row["generated_at"],
            }
            item.update(json.loads(row["metadata_json"] or "{}"))
            results.append(item)
        return results

    def record_publication(self, publication_type, natural_id, path, generated_at, metadata=None, export=True):
        payload = json.dumps(metadata or {}, ensure_ascii=False)
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO publications(publication_type, natural_id, path, generated_at, metadata_json)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(publication_type, natural_id)
                DO UPDATE SET path = excluded.path, generated_at = excluded.generated_at, metadata_json = excluded.metadata_json
                """,
                (publication_type, natural_id, path, generated_at, payload),
            )
        if export:
            self.export_legacy_state()

    def has_enrichment(self, enrichment_type, natural_id, target_path):
        row = self.conn.execute(
            "SELECT 1 FROM enrichments WHERE enrichment_type = ? AND natural_id = ? AND target_path = ?",
            (enrichment_type, natural_id, target_path),
        ).fetchone()
        return row is not None

    def record_enrichment(self, enrichment_type, natural_id, target_path, applied_at, metadata=None, export=True):
        payload = json.dumps(metadata or {}, ensure_ascii=False)
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO enrichments(enrichment_type, natural_id, target_path, applied_at, metadata_json)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(enrichment_type, natural_id, target_path)
                DO UPDATE SET applied_at = excluded.applied_at, metadata_json = excluded.metadata_json
                """,
                (enrichment_type, natural_id, target_path, applied_at, payload),
            )
        if export:
            self.export_legacy_state()

    def record_coverage(self, flow_name, item_kind, natural_id, covered_at, metadata=None, export=False):
        payload = json.dumps(metadata or {}, ensure_ascii=False)
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO coverage_state(flow_name, item_kind, natural_id, covered_at, metadata_json)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(flow_name, item_kind, natural_id)
                DO UPDATE SET covered_at = excluded.covered_at, metadata_json = excluded.metadata_json
                """,
                (flow_name, item_kind, natural_id, covered_at, payload),
            )
        if export:
            self.export_legacy_state()

    def covered_ids(self, flow_name, item_kind):
        rows = self.conn.execute(
            "SELECT natural_id FROM coverage_state WHERE flow_name = ? AND item_kind = ?",
            (flow_name, item_kind),
        ).fetchall()
        return {row["natural_id"] for row in rows}

    def set_cursor(self, cursor_key, value):
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO cursor_state(cursor_key, value_json)
                VALUES (?, ?)
                ON CONFLICT(cursor_key)
                DO UPDATE SET value_json = excluded.value_json
                """,
                (cursor_key, json.dumps(value, ensure_ascii=False)),
            )

    def get_cursor(self, cursor_key, default=None):
        row = self.conn.execute(
            "SELECT value_json FROM cursor_state WHERE cursor_key = ?",
            (cursor_key,),
        ).fetchone()
        if row is None:
            return default
        return json.loads(row["value_json"])

    def bulletin_cursor(self):
        return {
            "last_bulletin_at": self.get_cursor("bulletin.last_bulletin_at"),
            "covered": {
                kind: sorted(self.covered_ids("bulletin", kind))
                for kind in ("cve", "kev", "apt")
            },
        }

    def record_bulletin_fact(self, bulletin_path, fact_key, fact_kind, natural_id, fact_text, source_url, created_at):
        with self.conn:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO bulletin_facts(
                    bulletin_path, fact_key, fact_kind, natural_id, fact_text, source_url, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (bulletin_path, fact_key, fact_kind, natural_id, fact_text, source_url, created_at),
            )

    def export_legacy_state(self):
        cve_used = [
            {
                "id": item["natural_id"],
                "drafted_at": item["generated_at"],
                "path": item["path"],
            }
            for item in self.list_publications(PUBLICATION_TYPES["cve"])
        ]
        apt_used = [
            {
                "attack_id": item["natural_id"],
                "name": item.get("name"),
                "drafted_at": item["generated_at"],
                "path": item["path"],
            }
            for item in self.list_publications(PUBLICATION_TYPES["apt"])
        ]
        kev_used = [
            {
                "cve_id": item["natural_id"],
                "drafted_at": item["generated_at"],
                "path": item["path"],
            }
            for item in self.list_publications(PUBLICATION_TYPES["kev"])
        ]
        bulletin_state = self.bulletin_cursor()

        atomic_write_json(os.path.join(self.root, self.config["state_file"]), {"used": cve_used})
        atomic_write_json(os.path.join(self.root, self.config["apt_state_file"]), {"used": apt_used})
        atomic_write_json(os.path.join(self.root, self.config["kev_state_file"]), {"used": kev_used})
        atomic_write_json(os.path.join(self.root, self.config["bulletin_state_file"]), bulletin_state)
