import asyncio
from typing import Dict, List, Set, Any
from starlette.websockets import WebSocket
from .database import get_user_by_username


class RoutingCache:
    def __init__(self):
        self.active_sockets: Dict[str, List[WebSocket]] = {}
        self.user_cache: Dict[str, Dict[str, Any]] = {}
        self.channel_members: Dict[int, Set[str]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, username: str, websocket: WebSocket):
        async with self._lock:
            if username not in self.active_sockets:
                self.active_sockets[username] = []
            self.active_sockets[username].append(websocket)

    async def disconnect(self, username: str, websocket: WebSocket):
        async with self._lock:
            if username in self.active_sockets:
                if websocket in self.active_sockets[username]:
                    self.active_sockets[username].remove(websocket)
                if not self.active_sockets[username]:
                    del self.active_sockets[username]

    def get_user_sockets(self, username: str) -> List[WebSocket]:
        return self.active_sockets.get(username, [])

    def get_or_load_user(self, username: str) -> Dict[str, Any] | None:
        if username in self.user_cache:
            return self.user_cache[username]

        user = get_user_by_username(username)
        if user:
            self.user_cache[username] = user
            return user
        return None

    def invalidate_user(self, username: str):
        self.user_cache.pop(username, None)

    async def subscribe_channel(self, channel_id: int, username: str):
        async with self._lock:
            if channel_id not in self.channel_members:
                self.channel_members[channel_id] = set()
            self.channel_members[channel_id].add(username)

    async def unsubscribe_channel(self, channel_id: int, username: str):
        async with self._lock:
            if channel_id in self.channel_members:
                self.channel_members[channel_id].discard(username)

    def get_channel_subscribers(self, channel_id: int) -> Set[str]:
        return self.channel_members.get(channel_id, set())

    async def broadcast_to_channel(self, channel_id: int, payload: dict):
        subscribers = self.get_channel_subscribers(channel_id)
        for user in subscribers:
            sockets = self.get_user_sockets(user)
            for ws in sockets:
                try:
                    await ws.send_json(payload)
                except Exception:
                    pass

    async def send_direct_message(self, recipient_username: str, payload: dict) -> bool:
        sockets = self.get_user_sockets(recipient_username)
        delivered = False
        for ws in sockets:
            try:
                await ws.send_json(payload)
                delivered = True
            except Exception:
                pass
        return delivered


router = RoutingCache()
