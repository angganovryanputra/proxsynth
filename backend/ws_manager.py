"""
Proxsynth - WebSocket Full-Duplex Frame Interception & Replayer
Captures, audits, and replays WebSocket frame traffic (CLIENT_TO_SERVER, SERVER_TO_CLIENT)
for security testing real-time communication channels and socket endpoints.
"""

import json
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
import websockets

from backend.database import SessionLocal, WebSocketFrameLog


def record_ws_frame(
    project: str = "default",
    url: str = "",
    direction: str = "CLIENT_TO_SERVER",
    opcode: str = "TEXT",
    payload: str = ""
) -> Dict[str, Any]:
    """Persists an observed WebSocket frame into SQLite."""
    target_project = (project or "default").strip().lower()
    db = SessionLocal()
    try:
        frame = WebSocketFrameLog(
            project=target_project,
            url=url,
            direction=direction.upper(),
            opcode=opcode.upper(),
            payload=payload[:65536] if payload else ""
        )
        db.add(frame)
        db.commit()
        db.refresh(frame)
        return frame.to_dict()
    finally:
        db.close()


def list_ws_frames(
    project: str = "default",
    url: Optional[str] = None,
    limit: int = 50
) -> List[Dict[str, Any]]:
    """Retrieves logged WebSocket frames for analysis."""
    target_project = (project or "default").strip().lower()
    db = SessionLocal()
    try:
        query = db.query(WebSocketFrameLog).filter(WebSocketFrameLog.project == target_project)
        if url:
            query = query.filter(WebSocketFrameLog.url.ilike(f"%{url.strip()}%"))
        frames = query.order_by(WebSocketFrameLog.id.desc()).limit(min(limit, 200)).all()
        return [f.to_dict() for f in frames]
    finally:
        db.close()


async def send_ws_message(
    url: str,
    message: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 5.0,
    project: str = "default"
) -> Dict[str, Any]:
    """
    Connects to target WebSocket endpoint, dispatches a test message frame,
    captures the incoming response frame, and logs both to the database.
    """
    clean_url = url.strip()
    target_project = (project or "default").strip().lower()

    # Record outbound frame
    record_ws_frame(
        project=target_project,
        url=clean_url,
        direction="CLIENT_TO_SERVER",
        opcode="TEXT",
        payload=message
    )

    extra_headers = headers or {}
    try:
        async with websockets.connect(
            clean_url,
            extra_headers=extra_headers,
            ping_interval=None,
            close_timeout=timeout
        ) as ws:
            await ws.send(message)
            try:
                response = await asyncio.wait_for(ws.recv(), timeout=timeout)
                resp_text = str(response)

                # Record inbound frame
                record_ws_frame(
                    project=target_project,
                    url=clean_url,
                    direction="SERVER_TO_CLIENT",
                    opcode="TEXT",
                    payload=resp_text
                )

                return {
                    "success": True,
                    "url": clean_url,
                    "sent_message": message,
                    "received_message": resp_text,
                    "status": "EXCHANGED"
                }
            except asyncio.TimeoutError:
                return {
                    "success": True,
                    "url": clean_url,
                    "sent_message": message,
                    "received_message": None,
                    "status": "SENT_NO_REPLY_TIMEOUT"
                }
    except Exception as ex:
        return {
            "success": False,
            "url": clean_url,
            "error": str(ex),
            "status": "CONNECTION_FAILED"
        }
