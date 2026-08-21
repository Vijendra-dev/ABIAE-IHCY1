"""
openSquat Standalone Background Worker.
Can be executed as a dedicated worker process in Docker or as a CLI job:
- Runs ad-hoc or scheduled brand scans.
- Ingests pending JSON scan files from data/ directory.
- Analyzes newly discovered domains with TrustLens and Antigravity.
"""

import argparse
import asyncio
import glob
import logging
import os
import sys
import time

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import settings
from db import AsyncSessionLocal, init_db
from models import ScanRecord
from services.opensquat_runner import OpenSquatRunner
from tasks.process_domains import DomainThreatProcessor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("opensquat_worker")


async def run_immediate_scan(brands=None, confidence_threshold=0.70):
    """
    Executes a complete scan and processing cycle.
    """
    await init_db()
    runner = OpenSquatRunner()
    processor = DomainThreatProcessor()

    target_brands = brands or (
        settings.BRAND_LIST if isinstance(settings.BRAND_LIST, list) else ["google", "paypal", "microsoft"]
    )
    logger.info("Executing immediate worker scan for brands: %s", target_brands)

    async with AsyncSessionLocal() as session:
        # Create scan record
        scan = ScanRecord(brand_list=target_brands, status="RUNNING")
        session.add(scan)
        await session.commit()
        await session.refresh(scan)

        # Run openSquat
        scan_res = runner.execute_scan(
            brands=target_brands,
            confidence_threshold=confidence_threshold,
            scan_id=scan.id
        )
        scan.output_file = scan_res["filepath"]
        await session.commit()

        # Ingest and deep analyze
        cases = await processor.ingest_and_process_scan(
            session=session,
            scan_id=scan.id,
            threats_data=scan_res["results"],
        )
        await session.commit()

        logger.info("Worker scan %s finished: %d threats found, %d cases generated.", scan.id, len(scan_res["results"]), len(cases))
        return scan.id, cases


async def watch_and_process_data_dir(poll_interval: int = 15):
    """
    Continuous background loop that monitors data/ directory for new JSON scan files
    and processes pending domain threats.
    """
    await init_db()
    processor = DomainThreatProcessor()
    processed_files = set()
    logger.info("Starting openSquat worker folder watch on: %s (interval=%ds)", settings.DATA_DIR, poll_interval)

    while True:
        try:
            json_files = glob.glob(os.path.join(settings.DATA_DIR, "*opensquat.json"))
            for filepath in json_files:
                if filepath not in processed_files:
                    logger.info("Discovered new scan file: %s", filepath)
                    async with AsyncSessionLocal() as session:
                        try:
                            cases = await processor.process_file(session, filepath)
                            await session.commit()
                            logger.info("Processed %d cases from file %s", len(cases), filepath)
                            processed_files.add(filepath)
                        except Exception as e:
                            logger.error("Error processing file %s: %s", filepath, e)
                            await session.rollback()
        except Exception as e:
            logger.error("Error in worker watch loop: %s", e)

        await asyncio.sleep(poll_interval)


def main():
    parser = argparse.ArgumentParser(description="openSquat Background Worker")
    parser.add_argument("--scan-now", action="store_true", help="Run an immediate brand scan and exit")
    parser.add_argument("--brands", nargs="+", help="Brand names to scan for")
    parser.add_argument("--threshold", type=float, default=0.70, help="Confidence threshold (0.0 to 1.0)")
    parser.add_argument("--watch", action="store_true", help="Run continuous watcher loop")
    parser.add_argument("--poll-interval", type=int, default=15, help="Seconds between folder checks")

    args = parser.parse_args()

    if args.scan_now:
        asyncio.run(run_immediate_scan(brands=args.brands, confidence_threshold=args.threshold))
    elif args.watch or len(sys.argv) == 1:
        asyncio.run(watch_and_process_data_dir(poll_interval=args.poll_interval))


if __name__ == "__main__":
    main()
