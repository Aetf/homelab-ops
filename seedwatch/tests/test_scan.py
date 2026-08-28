"""Unit tests for the pure classification / reap-planning logic."""

import time

from seedwatch.scan import (
    FileState,
    Status,
    Torrent,
    classify,
    cross_seed_groups,
    plan_reaps,
    reap_eligible,
    wants_autotag,
)

MANAGED = frozenset({"动漫", "剧场版", "剧集", "电影"})
NOW = 1_700_000_000.0
OLD = int(NOW - 7 * 86400)


def mk_file(path="/d/a.mkv", nlink=2, selected=True, size=1000):
    return FileState(path=path, selected=selected,
                     is_media=path.endswith((".mkv", ".mp4")), nlink=nlink, size=size)


def mk_torrent(files, category="电影", tags=(), ratio=1.0, completion_on=OLD,
               amount_left=0, seeding_time=0, hash_="h1", name="t1", tracker="tr.example.org"):
    return Torrent(hash=hash_, name=name, category=category, tags=frozenset(tags),
                   ratio=ratio, size=sum(f.size for f in files), completion_on=completion_on,
                   seeding_time=seeding_time, amount_left=amount_left,
                   tracker_host=tracker, files=tuple(files))


def cls(t, grace_hours=24.0):
    return classify(t, managed=MANAGED, now=NOW, grace_hours=grace_hours)


def test_incomplete_never_judged_by_nlink():
    t = mk_torrent([mk_file(nlink=1)], amount_left=10)
    assert cls(t).status is Status.INCOMPLETE
    # completion_on unset counts as incomplete too
    t2 = mk_torrent([mk_file(nlink=1)], completion_on=0)
    assert cls(t2).status is Status.INCOMPLETE


def test_grace_period_after_completion():
    t = mk_torrent([mk_file(nlink=1)], completion_on=int(NOW - 3600))
    assert cls(t).status is Status.GRACE
    assert not wants_autotag(t, cls(t))


def test_unmanaged_category_untouched():
    t = mk_torrent([mk_file(nlink=1)], category="Mov")
    assert cls(t).status is Status.UNMANAGED
    assert not wants_autotag(t, cls(t))


def test_unreferenced_wants_autotag():
    t = mk_torrent([mk_file(nlink=1)])
    v = cls(t)
    assert v.status is Status.UNREFERENCED
    assert wants_autotag(t, v)


def test_existing_tags_veto_autotag():
    for tag in ("ToDelete", "Keep"):
        t = mk_torrent([mk_file(nlink=1)], tags=[tag])
        assert not wants_autotag(t, cls(t))


def test_referenced_and_partial():
    ref = mk_torrent([mk_file("/d/a.mkv", 2), mk_file("/d/b.mkv", 2)])
    assert cls(ref).status is Status.REFERENCED
    # deleted file is main-video-sized: genuine partial, human adjudication
    part = mk_torrent([mk_file("/d/a.mkv", 2), mk_file("/d/b.mkv", 1, size=900)])
    v = cls(part)
    assert v.status is Status.PARTIAL
    assert v.media_unref == 1 and v.unref_bytes == 900
    assert not wants_autotag(part, v)


def test_trimmed_extras_not_partial():
    # only minor extras deleted (sample/NCOP): no adjudication needed
    t = mk_torrent([mk_file("/d/movie.mkv", 2, size=10000),
                    mk_file("/d/sample.mkv", 1, size=80),
                    mk_file("/d/ncop.mkv", 1, size=300)])
    v = cls(t)
    assert v.status is Status.TRIMMED
    assert v.media_unref == 2 and v.unref_bytes == 380
    assert not wants_autotag(t, v)
    # one episode-sized deletion among the extras flips it back to PARTIAL
    t2 = mk_torrent([mk_file("/d/ep1.mkv", 2, size=1000),
                     mk_file("/d/ep2.mkv", 1, size=1000),
                     mk_file("/d/ncop.mkv", 1, size=100)])
    assert cls(t2).status is Status.PARTIAL
    # threshold is relative to the largest *referenced* file
    t3 = mk_torrent([mk_file("/d/small.mkv", 2, size=100),
                     mk_file("/d/big.mkv", 1, size=100)])
    assert cls(t3).status is Status.PARTIAL


def test_trimmed_tag_overrides_size_heuristic():
    # human verdict: episode-sized deletion is intentional
    t = mk_torrent([mk_file("/d/ep1.mkv", 2, size=1000),
                    mk_file("/d/ep2.mkv", 1, size=1000)], tags=["Trimmed"])
    assert cls(t).status is Status.TRIMMED
    # ...but once Media drops everything, autotag still applies
    t2 = mk_torrent([mk_file("/d/ep1.mkv", 1, size=1000)], tags=["Trimmed"])
    v = cls(t2)
    assert v.status is Status.UNREFERENCED
    assert wants_autotag(t2, v)


def test_unselected_and_nonmedia_files_ignored():
    t = mk_torrent([
        mk_file("/d/a.mkv", 1),
        mk_file("/d/skip.mkv", 5, selected=False),  # not downloaded
        mk_file("/d/info.nfo", 5),                  # not media
    ])
    assert cls(t).status is Status.UNREFERENCED


def test_missing_file_is_anomaly_not_autotag():
    t = mk_torrent([mk_file(nlink=None)])
    v = cls(t)
    assert v.status is Status.MISSING
    assert not wants_autotag(t, v)


def test_reap_gate_tag_plus_ratio():
    v = cls(mk_torrent([mk_file(nlink=1)]))
    t = mk_torrent([mk_file(nlink=1)], tags=["ToDelete"], ratio=4.2)
    assert reap_eligible(t, v, ratio_target=4.0, or_seed_days=None)
    low = mk_torrent([mk_file(nlink=1)], tags=["ToDelete"], ratio=3.9)
    assert not reap_eligible(low, v, ratio_target=4.0, or_seed_days=None)
    untagged = mk_torrent([mk_file(nlink=1)], ratio=9.9)
    assert not reap_eligible(untagged, v, ratio_target=4.0, or_seed_days=None)
    keep = mk_torrent([mk_file(nlink=1)], tags=["ToDelete", "Keep"], ratio=9.9)
    assert not reap_eligible(keep, v, ratio_target=4.0, or_seed_days=None)


def test_reap_still_referenced_is_legit():
    # deleting the Downloads hardlink never harms Media
    t = mk_torrent([mk_file(nlink=2)], tags=["ToDelete"], ratio=5.0)
    assert reap_eligible(t, cls(t), ratio_target=4.0, or_seed_days=None)


def test_reap_seed_days_fallback():
    t = mk_torrent([mk_file(nlink=1)], tags=["ToDelete"], ratio=0.5,
                   seeding_time=40 * 86400)
    v = cls(t)
    assert not reap_eligible(t, v, ratio_target=4.0, or_seed_days=None)
    assert reap_eligible(t, v, ratio_target=4.0, or_seed_days=30)


def test_plan_reaps_cross_seed_survivor_keeps_files():
    shared = mk_file("/d/x.mkv", 1)
    victim = mk_torrent([shared], hash_="v", name="victim", tags=["ToDelete"], ratio=5)
    survivor = mk_torrent([shared, mk_file("/d/y.mkv", 1)], hash_="s", name="survivor")
    [action] = plan_reaps([victim], [victim, survivor])
    assert not action.delete_files
    assert action.shared_with == ("survivor",)


def test_plan_reaps_both_candidates_last_one_deletes():
    shared = mk_file("/d/x.mkv", 1)
    a = mk_torrent([shared], hash_="a", name="a", tags=["ToDelete"], ratio=5)
    b = mk_torrent([shared], hash_="b", name="b", tags=["ToDelete"], ratio=5)
    first, second = plan_reaps([a, b], [a, b])
    assert not first.delete_files      # b still holds the files
    assert second.delete_files         # last holder cleans up


def test_plan_reaps_independent_deletes_files():
    t = mk_torrent([mk_file()], hash_="a", name="a", tags=["ToDelete"], ratio=5)
    other = mk_torrent([mk_file("/d/other.mkv")], hash_="b", name="b")
    [action] = plan_reaps([t], [t, other])
    assert action.delete_files


def test_cross_seed_groups():
    shared = mk_file("/d/x.mkv")
    a = mk_torrent([shared], hash_="a", name="a")
    b = mk_torrent([shared], hash_="b", name="b")
    c = mk_torrent([mk_file("/d/z.mkv")], hash_="c", name="c")
    [group] = cross_seed_groups([a, b, c])
    assert group.names == ("a", "b")
