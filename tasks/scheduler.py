"""
APScheduler-based periodic scan scheduler for Brand Intelligence Backend.
"""

import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from config import settings
from db import AsyncSessionLocal
from models import ScanRecord
from services.opensquat_runner import OpenSquatRunner
from tasks.process_domains import DomainThreatProcessor

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()


async def scheduled_opensquat_scan_job():
    """
    Scheduled job that triggers openSquat scan for configured brand list,
    writes results, and executes deep TrustLens analysis.
    """
    logger.info("Executing scheduled openSquat brand scan job...")
    runner = OpenSquatRunner()
    processor = DomainThreatProcessor()

    async with AsyncSessionLocal() as session:
        try:
            # 1. Create Scan record
            brands = settings.BRAND_LIST if isinstance(settings.BRAND_LIST, list) else ["google", "paypal", "microsoft"]
            scan = ScanRecord(brand_list=brands, status="RUNNING")
            session.add(scan)
            await session.commit()
            await session.refresh(scan)

            # 2. Run openSquat
            scan_out = runner.execute_scan(brands=brands, scan_id=scan.id)
            scan.output_file = scan_out["filepath"]
            await session.commit()

            # 3. Process threats
            if settings.AUTO_TRIGGER_ANALYSIS:
                await processor.ingest_and_process_scan(
                    session=session,
                    scan_id=scan.id,
                    threats_data=scan_out["results"],
                )
                await session.commit()

            logger.info("Scheduled openSquat scan %s completed successfully.", scan.id)
        except Exception as e:
            logger.exception("Error in scheduled openSquat job: %s", e)
            await session.rollback()


def start_scheduler():
    """
    Initializes and starts the AsyncIOScheduler with configured cron schedule.
    """
    if not scheduler.running:
        try:
            # Parse cron expression (e.g. "0 0 * * *")
            cron_parts = settings.OPENSQUAT_CRON_SCHEDULE.strip().split()
            if len(cron_parts) == 5:
                minute, hour, day, month, day_of_week = cron_parts
                trigger = CronTrigger(
                    minute=minute,
                    hour=hour,
                    day=day,
                    month=month,
                    day_of_week=day_of_week
                )
            else:
                trigger = CronTrigger(hour="0", minute="0")

            scheduler.add_job(
                scheduled_opensquat_scan_job,
                trigger=trigger,
                id="opensquat_daily_scan",
                replace_existing=True,
                name="Daily openSquat Brand Monitoring",
            )
            scheduler.start()
            logger.info("Brand Intelligence scheduler started with cron: %s", settings.OPENSQUAT_CRON_SCHEDULE)
        except Exception as e:
            logger.warning("Failed to start scheduler with cron trigger: %s. Using default 24h interval.", e)
            scheduler.add_job(
                scheduled_opensquat_scan_job,
                "interval",
                hours=24,
                id="opensquat_daily_scan",
                replace_existing=True,
            )
            scheduler.start()


def stop_scheduler():
    """
    Gracefully stops the scheduler.
    """
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("Brand Intelligence scheduler stopped.")
