"""
PROXSYNTH - Distributed Multi-Agent Swarm Worker Pool
Orchestrates parallel crawling, targeted fuzzing, and security audits
across enterprise targets and speculative routes using an asynchronous Worker Pool Pattern.
"""

import asyncio
import logging
import time
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional

logger = logging.getLogger("proxsynth.worker_swarm")


class WorkerSwarm:
    """
    Asynchronous Worker Pool for concurrent security audits and crawling.
    Distributes endpoints/targets across N parallel worker tasks with shared state deduplication.
    """

    def __init__(
        self,
        targets: List[str],
        project: str = "default",
        concurrency: int = 3,
        goal: str = "high_risk_vulnerabilities",
        max_depth: int = 2
    ):
        self.targets = list(dict.fromkeys([t.strip() for t in targets if t and t.strip()]))
        self.project = (project or "default").strip().lower()
        self.concurrency = max(1, min(concurrency, 10))
        self.goal = goal
        self.max_depth = max_depth
        self.swarm_id = f"swarm_{uuid.uuid4().hex[:8]}"

        self.task_queue: asyncio.Queue = asyncio.Queue()
        for t in self.targets:
            self.task_queue.put_nowait(t)

        self.processed_targets: List[str] = []
        self.worker_reports: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()
        self.active_workers: int = 0
        self.is_running: bool = False

    async def _emit_telemetry(self, worker_id: int, message: str, level: str = "INFO"):
        """Broadcasts worker status to WebSocket terminal."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_line = f"[{timestamp}] [SWARM:{self.swarm_id}] [WORKER_{worker_id}] [{level}] {message}"
        logger.info(log_line)
        try:
            from backend.app import ws_manager
            await ws_manager.broadcast({
                "type": "TERMINAL_STREAM",
                "data": {
                    "source": "worker_swarm",
                    "swarm_id": self.swarm_id,
                    "worker_id": worker_id,
                    "project": self.project,
                    "message": message,
                    "level": level,
                    "timestamp": timestamp
                }
            })
        except Exception:
            pass

    async def _worker_loop(self, worker_id: int, mock_mode: bool = False):
        """Worker task consuming targets from queue."""
        await self._emit_telemetry(worker_id, f"Worker {worker_id} initialized and standing by.")
        while not self.task_queue.empty():
            try:
                target = self.task_queue.get_nowait()
            except asyncio.QueueEmpty:
                break

            await self._emit_telemetry(worker_id, f"Auditing target: {target}")
            start_t = time.time()
            findings_found = 0
            status = "SUCCESS"

            if mock_mode:
                await asyncio.sleep(0.01)
                findings_found = 1 if "admin" in target else 0
            else:
                try:
                    from backend.autopilot_engine import AutonomousAutoPilot
                    pilot = AutonomousAutoPilot(
                        target=target,
                        project=self.project,
                        goal=self.goal,
                        max_depth=self.max_depth,
                        auto_exploit=True
                    )
                    res = await pilot.run()
                    findings_found = res.get("confirmed_findings", 0)
                except Exception as ex:
                    status = f"ERROR: {str(ex)}"
                    logger.debug(f"Worker {worker_id} error auditing {target}: {ex}")

            duration_s = round(time.time() - start_t, 2)
            report = {
                "worker_id": worker_id,
                "target": target,
                "duration_seconds": duration_s,
                "findings_found": findings_found,
                "status": status
            }

            async with self._lock:
                self.processed_targets.append(target)
                self.worker_reports.append(report)

            self.task_queue.task_done()
            await self._emit_telemetry(
                worker_id,
                f"Finished target: {target} ({findings_found} findings, {duration_s}s)"
            )

        await self._emit_telemetry(worker_id, f"Worker {worker_id} finished all queued tasks.")

    async def run(self, mock_mode: bool = False) -> Dict[str, Any]:
        """Launches the swarm worker pool and waits for queue completion."""
        self.is_running = True
        start_time = time.time()
        workers = [
            asyncio.create_task(self._worker_loop(worker_id=i + 1, mock_mode=mock_mode))
            for i in range(min(self.concurrency, len(self.targets) or 1))
        ]

        await asyncio.gather(*workers, return_exceptions=True)
        self.is_running = False
        total_duration = round(time.time() - start_time, 2)

        total_findings = sum(r.get("findings_found", 0) for r in self.worker_reports)

        return {
            "status": "COMPLETED",
            "swarm_id": self.swarm_id,
            "project": self.project,
            "concurrency": self.concurrency,
            "total_targets": len(self.targets),
            "processed_count": len(self.processed_targets),
            "total_findings": total_findings,
            "total_duration_seconds": total_duration,
            "worker_reports": self.worker_reports
        }


async def run_autopilot_swarm(
    targets: List[str],
    project: str = "default",
    concurrency: int = 3,
    goal: str = "high_risk_vulnerabilities",
    max_depth: int = 2,
    mock_mode: bool = False
) -> Dict[str, Any]:
    """Helper function to execute an autonomous multi-target swarm audit."""
    swarm = WorkerSwarm(
        targets=targets,
        project=project,
        concurrency=concurrency,
        goal=goal,
        max_depth=max_depth
    )
    return await swarm.run(mock_mode=mock_mode)

