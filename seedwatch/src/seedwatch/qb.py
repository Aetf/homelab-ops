"""Minimal async qBittorrent Web API client.

Auth relies on the WebUI's localhost auth bypass (the service runs with
host networking on the same machine as qbittorrent-nox).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import aiohttp


class QBClient:
    def __init__(self, base_url: str, session: aiohttp.ClientSession) -> None:
        self._api = base_url.rstrip("/") + "/api/v2"
        self._session = session

    async def _get(self, path: str, **params: str) -> Any:
        async with self._session.get(self._api + path, params=params) as resp:
            resp.raise_for_status()
            return await resp.json()

    async def _post(self, path: str, data: dict[str, str]) -> None:
        async with self._session.post(self._api + path, data=data) as resp:
            resp.raise_for_status()

    async def torrents_info(self) -> list[dict[str, Any]]:
        return await self._get("/torrents/info")

    async def torrent_files(self, torrent_hash: str) -> list[dict[str, Any]]:
        return await self._get("/torrents/files", hash=torrent_hash)

    async def torrent_trackers(self, torrent_hash: str) -> list[dict[str, Any]]:
        return await self._get("/torrents/trackers", hash=torrent_hash)

    async def tracker_host(self, info: dict[str, Any]) -> str:
        """Hostname of the torrent's tracker; falls back to the trackers
        list when torrents/info leaves the field empty (multi-tracker)."""
        url = info.get("tracker", "")
        if not url:
            for tr in await self.torrent_trackers(info["hash"]):
                if tr["url"].startswith(("http", "udp")):
                    url = tr["url"]
                    break
        return urlparse(url).hostname or ""

    async def add_tags(self, torrent_hash: str, tags: str) -> None:
        await self._post("/torrents/addTags", {"hashes": torrent_hash, "tags": tags})

    async def remove_tags(self, torrent_hash: str, tags: str) -> None:
        await self._post("/torrents/removeTags", {"hashes": torrent_hash, "tags": tags})

    async def delete(self, torrent_hash: str, delete_files: bool) -> None:
        await self._post("/torrents/delete", {
            "hashes": torrent_hash,
            "deleteFiles": "true" if delete_files else "false",
        })
