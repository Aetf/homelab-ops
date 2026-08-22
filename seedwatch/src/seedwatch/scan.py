"""Pure classification logic: torrent + file stats -> lifecycle status.

Everything here is side-effect free and covered by unit tests; the inputs
(qBittorrent API payloads, stat results) are gathered by reconcile.py.

The core invariant: move.sh hardlinks a managed-category torrent's content
into Media on completion, so for a *settled* torrent st_nlink==1 on every
media file means Media no longer references it. "Settled" is doing real
work in that sentence — an incomplete, unselected, or freshly-completed
file also has nlink==1, which is why INCOMPLETE/GRACE/MISSING exist and
are never auto-tagged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

TAG_TODELETE = "ToDelete"
TAG_KEEP = "Keep"

MEDIA_EXT = {
    ".mkv", ".mp4", ".avi", ".m2ts", ".ts", ".wmv", ".mov", ".rmvb",
    ".flac", ".mp3", ".ape", ".wav", ".m4a", ".aac", ".ogg", ".webm", ".iso",
}


class Status(Enum):
    UNMANAGED = "unmanaged"      # category not handled by move.sh: never touch
    INCOMPLETE = "incomplete"    # still downloading
    GRACE = "grace"              # completed too recently to trust nlink
    MISSING = "missing"          # media file absent on disk: anomaly, report only
    NO_MEDIA = "no_media"        # managed category but no media files (archives etc.)
    REFERENCED = "referenced"    # all media files still linked from Media
    PARTIAL = "partial"          # some deleted, some kept: human adjudication
    UNREFERENCED = "unreferenced"  # Media dropped everything: auto-tag candidate


@dataclass(frozen=True)
class FileState:
    path: str          # absolute
    selected: bool     # download priority > 0
    is_media: bool
    nlink: int | None  # None = missing on disk
    size: int = 0


@dataclass(frozen=True)
class Torrent:
    hash: str
    name: str
    category: str
    tags: frozenset[str]
    ratio: float
    size: int
    completion_on: int    # unix ts; <=0 when not complete
    seeding_time: int     # seconds
    amount_left: int
    tracker_host: str
    files: tuple[FileState, ...]


@dataclass(frozen=True)
class Verdict:
    status: Status
    media_total: int = 0
    media_unref: int = 0
    unref_bytes: int = 0


def classify(t: Torrent, *, managed: frozenset[str], now: float, grace_hours: float) -> Verdict:
    if t.amount_left > 0 or t.completion_on <= 0:
        return Verdict(Status.INCOMPLETE)
    if t.category not in managed:
        return Verdict(Status.UNMANAGED)
    if now - t.completion_on < grace_hours * 3600:
        return Verdict(Status.GRACE)
    media = [f for f in t.files if f.selected and f.is_media]
    if not media:
        return Verdict(Status.NO_MEDIA)
    if any(f.nlink is None for f in media):
        return Verdict(Status.MISSING, media_total=len(media))
    unref = [f for f in media if f.nlink == 1]
    verdict = Verdict(
        status=(
            Status.REFERENCED if not unref
            else Status.UNREFERENCED if len(unref) == len(media)
            else Status.PARTIAL
        ),
        media_total=len(media),
        media_unref=len(unref),
        unref_bytes=sum(f.size for f in unref),
    )
    return verdict


def wants_autotag(t: Torrent, v: Verdict) -> bool:
    """UNREFERENCED and not already decided (either way) by a tag."""
    return (
        v.status is Status.UNREFERENCED
        and TAG_TODELETE not in t.tags
        and TAG_KEEP not in t.tags
    )


def reap_eligible(t: Torrent, v: Verdict, *, ratio_target: float,
                  or_seed_days: float | None) -> bool:
    """The tag is the sole authorization to delete; thresholds gate *when*.

    Deleting the Downloads side never harms Media (hardlinks), so a
    still-REFERENCED ToDelete torrent is a legitimate "stop seeding, keep
    the media" request, not a contradiction.
    """
    if TAG_TODELETE not in t.tags or TAG_KEEP in t.tags:
        return False
    if v.status is Status.INCOMPLETE:
        return False
    if t.ratio >= ratio_target:
        return True
    return or_seed_days is not None and t.seeding_time >= or_seed_days * 86400


@dataclass(frozen=True)
class ReapAction:
    torrent: Torrent
    delete_files: bool
    shared_with: tuple[str, ...] = ()  # other torrents still holding these files


def plan_reaps(candidates: list[Torrent], all_torrents: list[Torrent]) -> list[ReapAction]:
    """Order-aware cross-seed handling.

    A candidate whose content files are still claimed by any other live
    torrent — a non-candidate survivor, or a candidate not yet processed —
    deletes only its torrent entry and keeps the files. The last remaining
    holder deletes them for real. Processing in this order means a failure
    mid-pass never leaves a live torrent seeding vanished files.
    """
    owners: dict[str, set[str]] = {}
    for t in all_torrents:
        for f in t.files:
            owners.setdefault(f.path, set()).add(t.hash)
    by_hash = {t.hash: t for t in all_torrents}

    actions: list[ReapAction] = []
    for t in candidates:
        holders = {h for f in t.files for h in owners.get(f.path, set()) if h != t.hash}
        actions.append(ReapAction(
            torrent=t,
            delete_files=not holders,
            shared_with=tuple(sorted(by_hash[h].name for h in holders)),
        ))
        for f in t.files:  # processed: no longer a holder for later candidates
            owners.get(f.path, set()).discard(t.hash)
    return actions


@dataclass(frozen=True)
class CrossSeedGroup:
    names: tuple[str, ...]


def cross_seed_groups(torrents: list[Torrent]) -> list[CrossSeedGroup]:
    owners: dict[str, set[str]] = {}
    for t in torrents:
        for f in t.files:
            owners.setdefault(f.path, set()).add(t.name)
    groups = {tuple(sorted(names)) for names in owners.values() if len(names) > 1}
    return [CrossSeedGroup(g) for g in sorted(groups)]


@dataclass
class Report:
    """Everything the UI shows, computed in one scan pass."""
    generated_at: float
    dry_run: bool
    torrents: list[dict] = field(default_factory=list)
    cross_seed: list[tuple[str, ...]] = field(default_factory=list)
    orphans: list[dict] = field(default_factory=list)
    actions_taken: list[dict] = field(default_factory=list)


def is_media_file(name: str) -> bool:
    return Path(name).suffix.lower() in MEDIA_EXT
