"""Neo4j GraphRAG sync — encyclopedia + job evidence + parsed artifact edges."""

from __future__ import annotations

import json
import logging
from typing import Any

from app.config import get_settings
from app.db.sql_helpers import execute, fetchall, fetchone

log = logging.getLogger("neo4j_sync")

_driver = None
_driver_failed = False


def _get_driver():
    global _driver, _driver_failed
    if _driver_failed:
        return None
    if _driver is not None:
        return _driver
    settings = get_settings()
    try:
        from neo4j import GraphDatabase

        _driver = GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password))
        _driver.verify_connectivity()
        return _driver
    except Exception as exc:
        log.warning("Neo4j unavailable: %s", exc)
        _driver_failed = True
        return None


def neo4j_available() -> bool:
    return _get_driver() is not None


def _sync_parsed_edges(session, job_id: str, parsed_rows: list[dict]) -> int:
    """Create evidence-derived graph edges from parse results."""
    edges = 0
    for row in parsed_rows:
        norm = row.get("normalized")
        if isinstance(norm, str):
            try:
                norm = json.loads(norm)
            except json.JSONDecodeError:
                norm = [{"text": norm}]
        if not isinstance(norm, list):
            norm = [norm] if norm else []

        path = row.get("file_path", "")
        aid = row.get("encyclopedia_artifact_id")
        parser_name = row.get("parser_name", "")

        session.run(
            """
            MERGE (e:EvidenceFile {path: $path, job_id: $jid})
            SET e.parser = $parser
            """,
            path=path,
            jid=job_id,
            parser=parser_name,
        )

        for rec in norm[:20]:
            if not isinstance(rec, dict):
                continue
            if rec.get("executable") or rec.get("format") == "prefetch_scca":
                exe = rec.get("executable", "")
                session.run(
                    """
                    MERGE (p:Process {name: $name, job_id: $jid})
                    MERGE (e:EvidenceFile {path: $path, job_id: $jid})
                    MERGE (e)-[:PROVES_EXECUTION]->(p)
                    """,
                    name=exe,
                    jid=job_id,
                    path=path,
                )
                edges += 1
            if rec.get("target") or rec.get("target_paths"):
                target = rec.get("target") or (rec.get("target_paths") or [""])[0]
                session.run(
                    """
                    MERGE (f:File {path: $target})
                    MERGE (e:EvidenceFile {path: $path, job_id: $jid})
                    MERGE (e)-[:LINKS_TO]->(f)
                    """,
                    target=target[:500],
                    path=path,
                    jid=job_id,
                )
                edges += 1
            if rec.get("event_id"):
                session.run(
                    """
                    MERGE (ev:TimelineEvent {event_id: $eid, job_id: $jid})
                    MERGE (e:EvidenceFile {path: $path, job_id: $jid})
                    MERGE (e)-[:CONTAINS_EVENT]->(ev)
                    """,
                    eid=str(rec["event_id"]),
                    jid=job_id,
                    path=path,
                )
                edges += 1
            if rec.get("registry_key"):
                session.run(
                    """
                    MERGE (rk:RegistryKey {path: $rkey})
                    MERGE (e:EvidenceFile {path: $path, job_id: $jid})
                    MERGE (e)-[:STORES_KEY]->(rk)
                    """,
                    rkey=rec["registry_key"][:500],
                    path=path,
                    jid=job_id,
                )
                edges += 1
            if rec.get("user_profile"):
                session.run(
                    """
                    MERGE (u:UserAccount {name: $uname, job_id: $jid})
                    MERGE (e:EvidenceFile {path: $path, job_id: $jid})
                    MERGE (e)-[:BELONGS_TO_USER]->(u)
                    """,
                    uname=rec["user_profile"],
                    jid=job_id,
                    path=path,
                )
                edges += 1
            if rec.get("table"):
                session.run(
                    """
                    MERGE (db:Database {table: $tbl, job_id: $jid})
                    MERGE (e:EvidenceFile {path: $path, job_id: $jid})
                    MERGE (e)-[:HAS_TABLE]->(db)
                    """,
                    tbl=rec["table"],
                    jid=job_id,
                    path=path,
                )
                edges += 1

        if aid:
            session.run(
                """
                MERGE (a:Artifact {id: $aid})
                MERGE (e:EvidenceFile {path: $path, job_id: $jid})
                MERGE (e)-[:MAPS_TO_ENCYCLOPEDIA]->(a)
                """,
                aid=aid,
                path=path,
                jid=job_id,
            )
            edges += 1

    return edges


def sync_job_graph(db, job_id: str, *, schema_name: str) -> dict:
    driver = _get_driver()
    if driver is None:
        execute(
            db,
            """INSERT INTO graph_sync_state (job_id, status, error)
               VALUES (:jid, 'skipped', 'Neo4j unavailable')
               ON CONFLICT (job_id) DO UPDATE SET status='skipped', error='Neo4j unavailable'""",
            {"jid": job_id},
        )
        db.commit()
        return {"status": "skipped", "nodes": 0, "edges": 0}

    arts = fetchall(
        db,
        """SELECT encyclopedia_artifact_id, file_path, sha256 FROM job_artifacts
           WHERE job_id=:jid AND encyclopedia_artifact_id IS NOT NULL LIMIT 5000""",
        {"jid": job_id},
    )
    parsed_rows = fetchall(
        db,
        """SELECT ja.file_path, ja.encyclopedia_artifact_id, apr.parser_name, apr.normalized
           FROM job_artifacts ja
           JOIN artifact_parse_results apr ON apr.job_artifact_id = ja.id
           WHERE ja.job_id=:jid LIMIT 5000""",
        {"jid": job_id},
    )
    enc_rels = db.execute(
        __import__("sqlalchemy").text(
            "SELECT from_artifact_id, to_artifact_id, relationship_type FROM public.encyclopedia_relationships LIMIT 5000"
        )
    ).mappings().all()

    nodes = 0
    edges = 0

    def _mark_syncing() -> None:
        execute(
            db,
            """INSERT INTO graph_sync_state (job_id, nodes_synced, edges_synced, status, error)
               VALUES (:jid, :n, :e, 'syncing', NULL)
               ON CONFLICT (job_id) DO UPDATE SET
                 nodes_synced=EXCLUDED.nodes_synced, edges_synced=EXCLUDED.edges_synced,
                 status='syncing', error=NULL""",
            {"jid": job_id, "n": nodes, "e": edges},
        )
        db.commit()

    _mark_syncing()
    try:
        with driver.session() as session:
            session.run("MERGE (j:Job {id: $jid}) SET j.updated_at = datetime()", jid=job_id)
            nodes += 1

            for i, a in enumerate(arts):
                session.run(
                    """
                    MERGE (e:EvidenceFile {path: $path, job_id: $jid})
                    SET e.sha256 = $sha, e.artifact_id = $aid
                    WITH e
                    MERGE (a:Artifact {id: $aid})
                    MERGE (e)-[:MAPS_TO_ENCYCLOPEDIA]->(a)
                    MERGE (j:Job {id: $jid})-[:CONTAINS]->(e)
                    """,
                    path=a["file_path"],
                    jid=job_id,
                    sha=a.get("sha256"),
                    aid=a["encyclopedia_artifact_id"],
                )
                nodes += 2
                edges += 2
                if (i + 1) % 200 == 0:
                    _mark_syncing()

            for r in enc_rels:
                session.run(
                    """
                    MERGE (a:Artifact {id: $from})
                    MERGE (b:Artifact {id: $to})
                    MERGE (a)-[:RELATED_TO {type: $typ}]->(b)
                    """,
                    **{"from": r["from_artifact_id"], "to": r["to_artifact_id"], "typ": r["relationship_type"]},
                )
                edges += 1

            edges += _sync_parsed_edges(session, job_id, [dict(r) for r in parsed_rows])
    except Exception as exc:
        msg = str(exc).lower()
        if any(tok in msg for tok in ("unavailable", "refused", "connection", "timeout", "auth")):
            execute(
                db,
                """INSERT INTO graph_sync_state (job_id, status, error)
                   VALUES (:jid, 'skipped', :err)
                   ON CONFLICT (job_id) DO UPDATE SET status='skipped', error=:err""",
                {"jid": job_id, "err": f"Neo4j unavailable: {exc}"[:400]},
            )
            db.commit()
            return {"status": "skipped", "nodes": nodes, "edges": edges}
        raise

    execute(
        db,
        """INSERT INTO graph_sync_state (job_id, nodes_synced, edges_synced, last_sync_at, status, error)
           VALUES (:jid, :n, :e, NOW(), 'ok', NULL)
           ON CONFLICT (job_id) DO UPDATE SET
             nodes_synced=EXCLUDED.nodes_synced, edges_synced=EXCLUDED.edges_synced,
             last_sync_at=NOW(), status='ok', error=NULL""",
        {"jid": job_id, "n": nodes, "e": edges},
    )
    db.commit()
    # Kick entity/annotation/ontology immediately — do not wait for full corpus RAG.
    try:
        from app.services.pipeline_orchestrator import _rag_enrich_status

        enrich_done, enrich_busy = _rag_enrich_status(db, job_id)
        if not enrich_done and not enrich_busy:
            from app.tasks import rag_enrich_task

            rag_enrich_task.delay(schema_name, job_id)
    except Exception:
        pass
    return {"status": "ok", "nodes": nodes, "edges": edges}


def graph_expand(driver, artifact_ids: list[str], *, hops: int = 2) -> list[dict[str, Any]]:
    if not driver or not artifact_ids:
        return []
    hops = max(1, min(int(hops), 3))
    with driver.session() as session:
        result = session.run(
            f"""
            UNWIND $ids AS aid
            MATCH (a:Artifact {{id: aid}})
            OPTIONAL MATCH path = (a)-[*1..{hops}]-(related)
            RETURN DISTINCT related.id AS id, labels(related) AS labels
            LIMIT 50
            """,
            ids=artifact_ids,
        )
        return [{"id": r["id"], "labels": r["labels"]} for r in result if r.get("id")]
