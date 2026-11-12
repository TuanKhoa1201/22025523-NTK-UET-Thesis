"""SQLite review queue: model assessments never change human review state."""
import json
import sqlite3
from pathlib import Path
from .evidence import EvidenceError, StaleSourceError, check_current, now, digest, SourceTree


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _observe_snapshots(record):
    observed = {}
    snapshots = record.get("snapshots") if isinstance(record.get("snapshots"), dict) else {}
    for path in snapshots:
        try:
            _, data, _ = SourceTree(record["root"]).read(path)
            observed[path] = digest(data)
        except (OSError, ValueError, UnicodeError, RuntimeError):
            observed[path] = "MISSING_OR_UNREADABLE"
    return observed


class ReviewStore:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY, bundle TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS warnings(
                id TEXT PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES scans(id),
                evidence TEXT NOT NULL, assessment TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'OPEN' CHECK(state IN ('OPEN','CONFIRMED_TRUE','CONFIRMED_FALSE')));
            CREATE TABLE IF NOT EXISTS events(
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                warning_id TEXT NOT NULL REFERENCES warnings(id), actor TEXT NOT NULL,
                timestamp TEXT NOT NULL, action TEXT NOT NULL, reason TEXT NOT NULL,
                source_version TEXT NOT NULL, observed_version TEXT NOT NULL, evidence_sha256 TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS rejected_decisions(
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                warning_id TEXT NOT NULL REFERENCES warnings(id), actor TEXT NOT NULL,
                timestamp TEXT NOT NULL, attempted_action TEXT NOT NULL, reason TEXT NOT NULL,
                rejection_code TEXT NOT NULL, source_version TEXT NOT NULL,
                observed_version TEXT NOT NULL, detail TEXT NOT NULL);
        """)

    def close(self):
        self.db.close()

    def add(self, bundle, assessments):
        if len(assessments) != len(bundle["records"]):
            raise EvidenceError("assessment count differs from warning count")
        with self.db:
            # Never silently replace an existing run, assessment or human decision.
            self.db.execute("INSERT INTO scans VALUES (?,?)", (bundle["scan_sha256"], encode(bundle)))
            for record, assessment in zip(bundle["records"], assessments):
                self.db.execute("INSERT INTO warnings(id,scan_id,evidence,assessment) VALUES (?,?,?,?)",
                                (record["id"], bundle["scan_sha256"], encode(record), encode(assessment)))

    def scans(self):
        return [json.loads(row[0]) for row in self.db.execute("SELECT bundle FROM scans ORDER BY rowid")]

    def queue(self, include_all=False):
        # Only an explicit human false confirmation hides a row; no row is deleted.
        query = "SELECT id FROM warnings"
        if not include_all:
            query += " WHERE state != 'CONFIRMED_FALSE'"
        return [self.get(row[0]) for row in self.db.execute(query + " ORDER BY rowid")]

    def get(self, identifier):
        row = self.db.execute("SELECT * FROM warnings WHERE id=?", (identifier,)).fetchone()
        if row is None:
            raise EvidenceError("unknown warning ID")
        return {"id": row["id"], "state": row["state"], "evidence": json.loads(row["evidence"]),
                "assessment": json.loads(row["assessment"])}

    def history(self, identifier):
        self.get(identifier)
        return [dict(row) for row in self.db.execute(
            "SELECT * FROM events WHERE warning_id=? ORDER BY sequence", (identifier,))]

    def rejected_decisions(self, identifier):
        self.get(identifier)
        return [dict(row) for row in self.db.execute(
            "SELECT * FROM rejected_decisions WHERE warning_id=? ORDER BY sequence", (identifier,))]

    def _record_rejected_decision(self, identifier, actor, action, reason, rejection_code, snapshots, observed, detail):
        with self.db:
            self.db.execute(
                "INSERT INTO rejected_decisions("
                "warning_id,actor,timestamp,attempted_action,reason,rejection_code,source_version,observed_version,detail"
                ") VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    identifier,
                    actor.strip(),
                    now(),
                    action,
                    reason.strip(),
                    rejection_code,
                    encode(snapshots),
                    encode(observed),
                    encode(detail),
                ),
            )

    def decide(self, identifier, action, actor, reason):
        states = {"confirm-true": "CONFIRMED_TRUE", "confirm-false": "CONFIRMED_FALSE", "reopen": "OPEN"}
        if action not in states or not isinstance(actor, str) or not actor.strip() or not isinstance(reason, str) or not reason.strip():
            raise EvidenceError("valid action, human actor and nonempty reason required")
        stale_exc = None
        stale_snapshots = {}
        try:
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                item = self.get(identifier)
                record = item["evidence"]
                stale_snapshots = record.get("snapshots") or {}
                if action == "confirm-false":
                    if record["issues"]:
                        raise EvidenceError("incomplete evidence; rescan before confirming false")
                    try:
                        check_current(record)
                    except StaleSourceError:
                        raise
                    except (OSError, ValueError, RuntimeError) as exc:
                        raise EvidenceError("source unavailable/changed; rescan required: " + str(exc)) from exc
                observed = _observe_snapshots(record)
                if action == "confirm-false":
                    mismatched = [
                        p for p, v in record["snapshots"].items()
                        if observed.get(p) != (v.get("sha256") if isinstance(v, dict) else None)
                    ]
                    if mismatched:
                        expected = {p: v.get("sha256") for p, v in record["snapshots"].items() if isinstance(v, dict)}
                        raise StaleSourceError(
                            "source changed during review; rescan required: " + ", ".join(mismatched),
                            mismatched_paths=mismatched,
                            expected_hashes=expected,
                            observed_hashes=observed,
                        )
                self.db.execute(
                    "INSERT INTO events(warning_id,actor,timestamp,action,reason,source_version,observed_version,evidence_sha256) VALUES (?,?,?,?,?,?,?,?)",
                    (identifier, actor.strip(), now(), action, reason.strip(), encode(record["snapshots"]),
                     encode(observed), digest(encode(record).encode("utf-8"))),
                )
                self.db.execute("UPDATE warnings SET state=? WHERE id=?", (states[action], identifier))
        except StaleSourceError as exc:
            stale_exc = exc
        if stale_exc is not None:
            self._record_rejected_decision(
                identifier,
                actor,
                action,
                reason,
                stale_exc.error_code,
                stale_snapshots,
                stale_exc.observed_hashes,
                stale_exc.to_dict(),
            )
            raise stale_exc
        return self.get(identifier)
