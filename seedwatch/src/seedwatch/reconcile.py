"""One reconcile pass: gather state, classify, act, report.

Rule 1 (auto-tag): a settled managed-category torrent whose media files
are all nlink==1 gets ToDelete (Keep vetoes; already-tagged untouched).

Rule 2 (reap): ToDelete + tracker ratio target met (or optional seed-time
fallback) -> delete via the qB API, cross-seed aware. The tag — whether
placed by rule 1, by the user in qB, or via the web UI — is the sole
authorization to delete; dry_run additionally suppresses both rules'
mutations while still reporting what would happen.

File deletion is delegated entirely to qBittorrent; this process only
ever stats the Downloads tree.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

from .config import Config
from .qb import QBClient
from .scan import (
    TAG_TODELETE,
    FileState,
    Report,
    Torrent,
    Verdict,
    classify,
    cross_seed_groups,
    is_media_file,
    plan_reaps,
    reap_eligible,
    wants_autotag,
)

log = logging.getLogger("seedwatch")


def _stat_files(save_path: str, files: list[dict[str, Any]]) -> tuple[FileState, ...]:
    out = []
    for f in files:
        p = Path(save_path) / f["name"]
        nlink: int | None
        size = f.get("size", 0)
        try:
            st = p.stat()
            nlink, size = st.st_nlink, st.st_size
        except OSError:
            nlink = None
        out.append(FileState(
            path=str(p),
            selected=f.get("priority", 1) != 0,
            is_media=is_media_file(f["name"]),
            nlink=nlink,
            size=size,
        ))
    return tuple(out)


async def gather_torrents(qb: QBClient, cfg: Config) -> list[Torrent]:
    infos = await qb.torrents_info()
    torrents: list[Torrent] = []
    for info in infos:
        files = await qb.torrent_files(info["hash"])
        states = await asyncio.to_thread(_stat_files, info["save_path"], files)
        torrents.append(Torrent(
            hash=info["hash"],
            name=info["name"],
            category=info["category"],
            tags=frozenset(t.strip() for t in info["tags"].split(",") if t.strip()),
            ratio=info["ratio"],
            size=info["size"],
            completion_on=info.get("completion_on", 0),
            seeding_time=info.get("seeding_time", 0),
            amount_left=info["amount_left"],
            tracker_host=await qb.tracker_host(info),
            files=states,
        ))
    return torrents


def _scan_orphans(downloads: Path, claimed: set[str]) -> list[dict[str, Any]]:
    orphans = []
    for root, _dirs, names in os.walk(downloads):
        for name in names:
            p = os.path.join(root, name)
            if p in claimed or p == str(downloads / "move.sh"):
                continue
            try:
                size = os.lstat(p).st_size
            except OSError:
                continue
            orphans.append({"path": p, "size": size})
    return orphans


class Auditor:
    """Append-only JSONL log of every mutation (and dry-run intent)."""

    def __init__(self, data_dir: Path) -> None:
        data_dir.mkdir(parents=True, exist_ok=True)
        self._path = data_dir / "audit.jsonl"

    def record(self, action: str, t: Torrent, *, dry_run: bool, **extra: Any) -> dict[str, Any]:
        entry = {
            "ts": time.time(),
            "action": action,
            "dry_run": dry_run,
            "hash": t.hash,
            "name": t.name,
            "category": t.category,
            "ratio": round(t.ratio, 3),
            **extra,
        }
        with open(self._path, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def tail(self, n: int = 200) -> list[dict[str, Any]]:
        if not self._path.is_file():
            return []
        with open(self._path) as f:
            lines = f.readlines()[-n:]
        return [json.loads(line) for line in lines]


def _torrent_row(t: Torrent, v: Verdict, cfg: Config) -> dict[str, Any]:
    policy = cfg.tracker_policy(t.tracker_host)
    return {
        "hash": t.hash,
        "name": t.name,
        "category": t.category,
        "tags": sorted(t.tags),
        "ratio": round(t.ratio, 2),
        "size": t.size,
        "tracker": t.tracker_host,
        "ratio_target": policy.ratio,
        "seeding_days": round(t.seeding_time / 86400, 1),
        "status": v.status.value,
        "media_total": v.media_total,
        "media_unref": v.media_unref,
        "unref_bytes": v.unref_bytes,
    }


async def reconcile(qb: QBClient, cfg: Config, auditor: Auditor) -> Report:
    now = time.time()
    torrents = await gather_torrents(qb, cfg)
    verdicts = {
        t.hash: classify(t, managed=cfg.managed_categories, now=now,
                         grace_hours=cfg.grace_hours,
                         extras_fraction=cfg.extras_fraction)
        for t in torrents
    }
    report = Report(generated_at=now, dry_run=cfg.dry_run)
    actions: list[dict[str, Any]] = []

    # Rule 1: auto-tag
    for i, t in enumerate(torrents):
        if not wants_autotag(t, verdicts[t.hash]):
            continue
        actions.append(auditor.record("autotag", t, dry_run=cfg.dry_run))
        if not cfg.dry_run:
            await qb.add_tags(t.hash, TAG_TODELETE)
            torrents[i] = replace(t, tags=t.tags | {TAG_TODELETE})
        log.info("autotag%s: %s", " (dry-run)" if cfg.dry_run else "", t.name)

    # Rule 2: reap
    candidates = []
    for t in torrents:
        policy = cfg.tracker_policy(t.tracker_host)
        if reap_eligible(t, verdicts[t.hash], ratio_target=policy.ratio,
                         or_seed_days=policy.or_seed_days):
            candidates.append(t)
    reaped: set[str] = set()
    for action in plan_reaps(candidates, torrents):
        t = action.torrent
        actions.append(auditor.record(
            "reap", t, dry_run=cfg.dry_run,
            delete_files=action.delete_files, shared_with=list(action.shared_with),
        ))
        if not cfg.dry_run:
            await qb.delete(t.hash, action.delete_files)
            reaped.add(t.hash)
        log.info("reap%s: %s (delete_files=%s)",
                 " (dry-run)" if cfg.dry_run else "", t.name, action.delete_files)
    remaining = [t for t in torrents if t.hash not in reaped]
    report.torrents = [_torrent_row(t, verdicts[t.hash], cfg) for t in remaining]
    report.cross_seed = [g.names for g in cross_seed_groups(remaining)]
    claimed = {f.path for t in remaining for f in t.files}
    report.orphans = await asyncio.to_thread(_scan_orphans, cfg.downloads, claimed)
    report.actions_taken = actions
    return report
