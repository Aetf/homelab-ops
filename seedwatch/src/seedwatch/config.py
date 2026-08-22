"""Config loading (TOML file + a few env overrides).

The config file is host policy, not code: mounted read-only into the
container from ~/.config/seedwatch/config.toml (yadm hostname alternate).
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class TrackerPolicy:
    ratio: float
    # A torrent on a dead/slow tracker may never reach the ratio target;
    # if set, seeding for this many days also satisfies the reap gate.
    or_seed_days: float | None = None


@dataclass(frozen=True)
class Config:
    qb_url: str = "http://127.0.0.1:9876"
    downloads: Path = Path("/mnt/nas/Downloads")
    # Only these categories are hardlinked into Media by move.sh; the
    # nlink criterion is meaningless for anything else.
    managed_categories: frozenset[str] = frozenset({"动漫", "剧场版", "剧集", "电影"})
    # Wait this long after completion before trusting nlink==1: covers the
    # window where move.sh has not run yet (or failed).
    grace_hours: float = 24.0
    scan_interval_minutes: float = 60.0
    dry_run: bool = True
    default_ratio: float = 4.0
    trackers: dict[str, TrackerPolicy] = field(default_factory=dict)
    listen_port: int = 8490
    data_dir: Path = Path("/data")

    def tracker_policy(self, host: str) -> TrackerPolicy:
        for suffix, policy in self.trackers.items():
            if host == suffix or host.endswith("." + suffix):
                return policy
        return TrackerPolicy(ratio=self.default_ratio)


def load_config() -> Config:
    path = os.environ.get("SEEDWATCH_CONFIG", "/config/config.toml")
    raw: dict = {}
    if Path(path).is_file():
        with open(path, "rb") as f:
            raw = tomllib.load(f)
    qb = raw.get("qbittorrent", {})
    scan = raw.get("scan", {})
    reap = raw.get("reap", {})
    trackers = {
        name: TrackerPolicy(
            ratio=float(t["ratio"]),
            or_seed_days=float(t["or_seed_days"]) if "or_seed_days" in t else None,
        )
        for name, t in reap.get("trackers", {}).items()
    }
    return Config(
        qb_url=os.environ.get("QB_URL", qb.get("url", Config.qb_url)),
        downloads=Path(scan.get("downloads", str(Config.downloads))),
        managed_categories=frozenset(
            scan.get("managed_categories", sorted(Config.managed_categories))
        ),
        grace_hours=float(scan.get("grace_hours", Config.grace_hours)),
        scan_interval_minutes=float(
            scan.get("interval_minutes", Config.scan_interval_minutes)
        ),
        dry_run=bool(reap.get("dry_run", Config.dry_run)),
        default_ratio=float(reap.get("default_ratio", Config.default_ratio)),
        trackers=trackers,
        listen_port=int(os.environ.get("PORT", raw.get("port", Config.listen_port))),
        data_dir=Path(os.environ.get("DATA_DIR", str(Config.data_dir))),
    )
