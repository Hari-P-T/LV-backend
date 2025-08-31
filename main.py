"""
FastAPI backend implementing Auth0-protected WebSocket-based N-device concurrent session control.

Features:
- Auth0 JWT verification (RS256) using JWKS
- WebSocket endpoint for real-time session tracking and forced logout
- Redis (async) used to persist active device lists per user
- In-memory mapping userId -> deviceId -> websocket for push notifications
- REST endpoint /api/profile to return user's full name and phone (requires valid Access Token)
"""

import os
import json
import asyncio
import logging
import time
import uuid
from typing import Dict, Any, Optional

import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt
import redis.asyncio as aioredis

# --- Configuration ---
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN", "YOUR_AUTH0_DOMAIN")
AUTH0_AUDIENCE = os.getenv("AUTH0_AUDIENCE", "YOUR_API_AUDIENCE")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
DEVICE_LIMIT = int(os.getenv("DEVICE_LIMIT", "3"))
JWKS_CACHE_TTL = 3600

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("n_device_backend")

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

redis = aioredis.from_url(REDIS_URL, decode_responses=True)

live_ws: Dict[str, Dict[str, WebSocket]] = {}
_jwks_cache: Optional[Dict[str, Any]] = None
_jwks_last_fetch = 0

async def fetch_jwks() -> Dict[str, Any]:
    global _jwks_cache, _jwks_last_fetch
    now = time.time()
    if _jwks_cache and (now - _jwks_last_fetch) < JWKS_CACHE_TTL:
        return _jwks_cache
    url = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(url)
        r.raise_for_status()
        _jwks_cache = r.json()
        _jwks_last_fetch = now
        return _jwks_cache

async def verify_jwt(token: str) -> Dict[str, Any]:
    jwks = await fetch_jwks()
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get("kid")
    if not kid:
        raise HTTPException(status_code=401, detail="Invalid token header")

    key = None
    for k in jwks.get("keys", []):
        if k.get("kid") == kid:
            key = k
            break
    if not key:
        raise HTTPException(status_code=401, detail="Public key not found")

    public_key = jwt.construct_rsa_public_key(key)

    try:
        claims = jwt.decode(token, public_key, algorithms=[key.get("alg", "RS256")], audience=AUTH0_AUDIENCE)
        return claims
    except Exception as e:
        logger.exception("JWT verification failed")
        raise HTTPException(status_code=401, detail=f"Token verification failed: {str(e)}")

async def redis_active_devices_key(user_id: str) -> str:
    return f"active_devices:{user_id}"

async def add_device_to_redis(user_id: str, device_id: str, meta: Dict[str, Any]):
    key = await redis_active_devices_key(user_id)
    await redis.hset(key, device_id, json.dumps(meta))
    await redis.expire(key, 60 * 60 * 24)

async def remove_device_from_redis(user_id: str, device_id: str):
    key = await redis_active_devices_key(user_id)
    await redis.hdel(key, device_id)

async def list_devices_from_redis(user_id: str) -> Dict[str, Any]:
    key = await redis_active_devices_key(user_id)
    raw = await redis.hgetall(key)
    out = {}
    for d, v in raw.items():
        try:
            out[d] = json.loads(v)
        except Exception:
            out[d] = {"raw": v}
    return out

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    params = websocket.query_params
    token = params.get("token")
    device_id = params.get("device_id") or str(uuid.uuid4())

    if not token:
        await websocket.send_json({"type": "error", "message": "missing token"})
        await websocket.close(code=4001)
        return

    try:
        claims = await verify_jwt(token)
    except HTTPException:
        await websocket.send_json({"type": "error", "message": "auth failed"})
        await websocket.close(code=4002)
        return

    user_id = claims.get("sub")
    full_name = claims.get("name") or ""
    phone = claims.get("phone_number") or ""

    devices = await list_devices_from_redis(user_id)
    device_count = len(devices)

    is_reconnect = device_id in devices

    if not is_reconnect and device_count >= DEVICE_LIMIT:
        await websocket.send_json({
            "type": "limit_reached",
            "message": f"Device limit of {DEVICE_LIMIT} reached",
            "sessions": [{"device_id": d, "meta": devices[d]} for d in devices],
        })
        await websocket.close()
        return

    meta = {"device_id": device_id, "created_at": int(time.time()), "full_name": full_name, "phone": phone}
    await add_device_to_redis(user_id, device_id, meta)

    if user_id not in live_ws:
        live_ws[user_id] = {}
    live_ws[user_id][device_id] = websocket

    await websocket.send_json({"type": "connected", "device_id": device_id, "message": "connected"})

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        logger.info(f"WS disconnect: user={user_id} device={device_id}")
    finally:
        live_ws.get(user_id, {}).pop(device_id, None)
        await remove_device_from_redis(user_id, device_id)

@app.get("/api/profile")
async def profile(authorization: Optional[str] = None):
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing")
    parts = authorization.split()
    if parts[0].lower() != "bearer" or len(parts) != 2:
        raise HTTPException(status_code=401, detail="Invalid auth header")
    token = parts[1]
    claims = await verify_jwt(token)
    return JSONResponse({"full_name": claims.get("name"), "phone": claims.get("phone_number")})

@app.get("/health")
async def health():
    return {"status": "ok", "device_limit": DEVICE_LIMIT}
