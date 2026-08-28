"""FastAPI app: periodic reconcile loop + report/adjudication web UI."""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path

import aiohttp
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

from .config import load_config
from .qb import QBClient
from .reconcile import Auditor, reconcile
from .scan import TAG_KEEP, TAG_TODELETE

log = logging.getLogger("seedwatch")
WEB_DIR = Path(__file__).resolve().parent.parent.parent / "web"

cfg = load_config()
auditor = Auditor(cfg.data_dir)
state: dict = {"report": None, "error": None, "scanning": False}
wakeup = asyncio.Event()


async def scan_loop(qb: QBClient) -> None:
    while True:
        state["scanning"] = True
        try:
            report = await reconcile(qb, cfg, auditor)
            state["report"] = asdict(report)
            state["error"] = None
        except Exception:
            log.exception("reconcile pass failed")
            state["error"] = {"ts": time.time(), "detail": "reconcile failed, see logs"}
        finally:
            state["scanning"] = False
        wakeup.clear()
        try:
            await asyncio.wait_for(wakeup.wait(), timeout=cfg.scan_interval_minutes * 60)
        except TimeoutError:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with aiohttp.ClientSession() as session:
        app.state.qb = QBClient(cfg.qb_url, session)
        task = asyncio.create_task(scan_loop(app.state.qb))
        try:
            yield
        finally:
            task.cancel()


app = FastAPI(title="seedwatch", lifespan=lifespan)


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


@app.get("/api/report")
async def get_report() -> dict:
    return {
        "report": state["report"],
        "error": state["error"],
        "scanning": state["scanning"],
        "dry_run": cfg.dry_run,
    }


@app.post("/api/rescan")
async def rescan() -> dict:
    wakeup.set()
    return {"ok": True}


VALID_TAGS = {TAG_TODELETE, TAG_KEEP}


def _patch_report_tags(torrent_hash: str, tag: str, *, add: bool) -> None:
    """Reflect a tag change in the cached report immediately.

    Tagging must not trigger a rescan: a full pass stats the whole
    Downloads tree for minutes, which blocks adjudicating the next
    torrent. The next periodic scan re-derives ground truth anyway.
    """
    rep = state["report"]
    if not rep:
        return
    for row in rep["torrents"]:
        if row["hash"] == torrent_hash:
            tags = set(row["tags"])
            (tags.add if add else tags.discard)(tag)
            row["tags"] = sorted(tags)


@app.post("/api/torrents/{torrent_hash}/tags/{tag}")
async def add_tag(torrent_hash: str, tag: str) -> dict:
    if tag not in VALID_TAGS:
        raise HTTPException(400, f"tag must be one of {sorted(VALID_TAGS)}")
    await app.state.qb.add_tags(torrent_hash, tag)
    _patch_report_tags(torrent_hash, tag, add=True)
    return {"ok": True}


@app.delete("/api/torrents/{torrent_hash}/tags/{tag}")
async def remove_tag(torrent_hash: str, tag: str) -> dict:
    if tag not in VALID_TAGS:
        raise HTTPException(400, f"tag must be one of {sorted(VALID_TAGS)}")
    await app.state.qb.remove_tags(torrent_hash, tag)
    _patch_report_tags(torrent_hash, tag, add=False)
    return {"ok": True}


@app.get("/api/audit")
async def audit_log() -> list[dict]:
    return auditor.tail()


def run() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    uvicorn.run(app, host="0.0.0.0", port=cfg.listen_port, log_level="warning")


if __name__ == "__main__":
    run()
