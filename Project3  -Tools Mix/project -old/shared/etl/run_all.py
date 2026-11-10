"""
run_all.py - Scheduler: runs all ETL jobs, then refreshes dedup view.
"""
import os
import time
import logging
import importlib
import psycopg2

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

ETL_INTERVAL = int(os.environ.get("ETL_INTERVAL", 3600))

JOBS = ["claroty_etl", "nessus_etl", "pits_etl"]


def refresh_view():
    from db import get_connection
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT refresh_unified_vulns();")
        conn.commit()
        logger.info("Refreshed unified_vulnerabilities view")
    except Exception as e:
        logger.warning(f"Could not refresh view: {e}")
    finally:
        conn.close()


def run_jobs():
    for job_name in JOBS:
        try:
            logger.info(f"Starting {job_name}...")
            mod = importlib.import_module(job_name)
            mod.run()
            logger.info(f"{job_name} completed")
        except Exception as e:
            logger.error(f"{job_name} failed: {e}")
    refresh_view()


if __name__ == "__main__":
    logger.info(f"ETL scheduler starting. Interval = {ETL_INTERVAL}s")
    while True:
        run_jobs()
        logger.info(f"Sleeping {ETL_INTERVAL}s until next run...")
        time.sleep(ETL_INTERVAL)
