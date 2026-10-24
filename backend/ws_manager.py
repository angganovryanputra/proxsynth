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
    project: str = "default",
    protocol: str = "raw",
    event_name: str = "message"
) -> Dict[str, Any]:
    """
    Connects to target WebSocket or Socket.IO endpoint, dispatches a test message frame,
    captures the incoming response frame, and logs all transactions to the database.

    Supported Protocols:
      - 'raw': Plain WebSocket frames.
      - 'socket.io': Engine.IO v4/v3 full handshake ('0' open -> '40' connect -> '42' event).
    """
    clean_url = url.strip()
    target_project = (project or "default").strip().lower()
    proto_mode = (protocol or "raw").strip().lower()

    # Normalize HTTP/HTTPS to WS/WSS
    if clean_url.startswith("http://"):
        clean_url = "ws://" + clean_url[7:]
    elif clean_url.startswith("https://"):
        clean_url = "wss://" + clean_url[8:]

    extra_headers = headers or {}

    # Handle Socket.IO / Engine.IO Protocol
    if proto_mode == "socket.io":
        if "/socket.io" not in clean_url:
            base = clean_url.rstrip("/")
            clean_url = f"{base}/socket.io/?EIO=4&transport=websocket"

        try:
            async with websockets.connect(
                clean_url,
                extra_headers=extra_headers,
                ping_interval=None,
                close_timeout=timeout
            ) as ws:
                # 1. Step 1: Wait for Engine.IO '0' open packet
                handshake_frame = await asyncio.wait_for(ws.recv(), timeout=timeout)
                handshake_text = str(handshake_frame)
                record_ws_frame(
                    project=target_project,
                    url=clean_url,
                    direction="SERVER_TO_CLIENT",
                    opcode="TEXT",
                    payload=handshake_text
                )

                sid = ""
                if handshake_text.startswith("0"):
                    try:
                        h_data = json.loads(handshake_text[1:])
                        sid = h_data.get("sid", "")
                    except Exception:
                        pass

                # 2. Step 2: Send Socket.IO '40' connect packet
                connect_packet = "40"
                await ws.send(connect_packet)
                record_ws_frame(
                    project=target_project,
                    url=clean_url,
                    direction="CLIENT_TO_SERVER",
                    opcode="TEXT",
                    payload=connect_packet
                )

                # 3. Format payload for Socket.IO event '42[event_name, data]'
                try:
                    parsed_payload = json.loads(message)
                except Exception:
                    parsed_payload = message

                framed_outbound = f'42["{event_name}", {json.dumps(parsed_payload)}]'
                await ws.send(framed_outbound)
                record_ws_frame(
                    project=target_project,
                    url=clean_url,
                    direction="CLIENT_TO_SERVER",
                    opcode="TEXT",
                    payload=framed_outbound
                )

                # 4. Await response (handle ping/pong if received)
                t_end = asyncio.get_event_loop().time() + timeout
                received_frame = None
                unpacked_event = None

                while asyncio.get_event_loop().time() < t_end:
                    remaining = max(0.5, t_end - asyncio.get_event_loop().time())
                    raw_in = await asyncio.wait_for(ws.recv(), timeout=remaining)
                    in_text = str(raw_in)
                    record_ws_frame(
                        project=target_project,
                        url=clean_url,
                        direction="SERVER_TO_CLIENT",
                        opcode="TEXT",
                        payload=in_text
                    )

                    if in_text.startswith("2"):  # Engine.IO ping -> reply pong
                        await ws.send("3")
                        continue

                    if in_text.startswith("42"):  # Socket.IO Event response
                        received_frame = in_text
                        try:
                            unpacked_event = json.loads(in_text[2:])
                        except Exception:
                            unpacked_event = in_text[2:]
                        break
                    elif in_text.startswith("40"):
                        # Ack connect, wait for actual event response
                        continue
                    else:
                        received_frame = in_text
                        break

                return {
                    "success": True,
                    "protocol": "socket.io",
                    "socket_io_sid": sid,
                    "event_name": event_name,
                    "url": clean_url,
                    "sent_message": message,
                    "sent_frame": framed_outbound,
                    "received_message": unpacked_event if unpacked_event is not None else received_frame,
                    "received_frame": received_frame,
                    "status": "EXCHANGED" if received_frame else "SENT_NO_REPLY_TIMEOUT"
                }

        except Exception as ex:
            return {
                "success": False,
                "protocol": "socket.io",
                "url": clean_url,
                "error": str(ex),
                "status": "CONNECTION_FAILED"
            }

    # Default Raw WebSocket Protocol
    record_ws_frame(
        project=target_project,
        url=clean_url,
        direction="CLIENT_TO_SERVER",
        opcode="TEXT",
        payload=message
    )

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

                record_ws_frame(
                    project=target_project,
                    url=clean_url,
                    direction="SERVER_TO_CLIENT",
                    opcode="TEXT",
                    payload=resp_text
                )

                return {
                    "success": True,
                    "protocol": "raw",
                    "url": clean_url,
                    "sent_message": message,
                    "received_message": resp_text,
                    "status": "EXCHANGED"
                }
            except asyncio.TimeoutError:
                return {
                    "success": True,
                    "protocol": "raw",
                    "url": clean_url,
                    "sent_message": message,
                    "received_message": None,
                    "status": "SENT_NO_REPLY_TIMEOUT"
                }
    except Exception as ex:
        return {
            "success": False,
            "protocol": "raw",
            "url": clean_url,
            "error": str(ex),
            "status": "CONNECTION_FAILED"
        }
