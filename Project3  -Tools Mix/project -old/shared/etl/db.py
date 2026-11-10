"""
db.py - Database connection helper
"""
import os
import psycopg2
import psycopg2.extras
import logging

logger = logging.getLogger(__name__)


def get_connection():
    return psycopg2.connect(
        dbname=os.environ.get("POSTGRES_DB", "vuln_db"),
        user=os.environ.get("POSTGRES_USER", "vuln_user"),
        password=os.environ.get("POSTGRES_PASSWORD", "StrongPassword123!"),
        host=os.environ.get("POSTGRES_HOST", "127.0.0.1"),
        port=int(os.environ.get("POSTGRES_PORT", 5432)),
        cursor_factory=psycopg2.extras.RealDictCursor,
    )


def log_etl_start(conn, source: str) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO etl_runs (source, started_at, status) VALUES (%s, NOW(), 'running') RETURNING id",
            (source,),
        )
        run_id = cur.fetchone()["id"]
    conn.commit()
    return run_id


def log_etl_end(conn, run_id: int, records: int, status: str = "success", error_msg: str = None):
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE etl_runs
            SET finished_at = NOW(), records = %s, status = %s, error_msg = %s
            WHERE id = %s
            """,
            (records, status, error_msg, run_id),
        )
    conn.commit()
