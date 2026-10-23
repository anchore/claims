"""Convert anchore/vulnerability-match-labels labels into claims corpus label files.

A vulnerability-match-labels label is one person's TP, FP or ?? on one vulnerability id reported on
one package (by name and version, or by location) of one image. A corpus label is one call on one
purl and vulnerability, in a file per image and package type. This module does that conversion and
nothing else: no network, no subprocesses, so it can be tested from fixtures alone.

What a label carries across:

- the verdict, author and time; every input call also becomes a note by its labeler at its time,
  naming its vulnerability-match-labels uuid, its verdict, its tool as written and its own note,
  so labels merged from several calls lose nothing
- seenIn.tools: the tool the call names, plus the syft vulnerability-match-labels' config pinned
  on that date (whose SBOM its grype result sets scanned)
- the package, as the purl of the artifact the image's SBOM holds at that name and version, or
  at the location a package-less label's fullentry_fields name
- an advisory id (by vocabulary.yaml's advisory-ids) stays the label's vulnerability, with the
  call's verdict: the call judged the match grype reported, and grype reports the advisory itself.
  It is never moved to the CVEs the advisory names, since not every one of them affects every
  package it lists. It is named as grype's DB names it today (ALAS-... on Amazon Linux 2 is
  ALAS2-...), and an advisory the DB does not hold is reported rather than guessed at

What does not: effective_cve, and an image's tag (labels name images by digest).
"""

import fnmatch
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from sboms import MATCHES

# the label file format this conversion writes, as in schema/matches/schema-<version>.json. It is the
# pinned yardstick's (`yardstick claims schema`), so bump it with the pin when the format moves.
SCHEMA_VERSION = "1.0.0"

# justifications this conversion writes; vocabulary.yaml defines them
NOT_RECORDED = "not-recorded"
LABELERS_DISAGREE = "labelers-disagree"

# outcomes: only the first wrote labels
MIGRATED = "migrated"
NO_PACKAGE, NO_SBOM, NOT_IN_SBOM, NO_PURL = "no-package", "no-sbom", "package-not-in-sbom", "package-has-no-purl"
NOT_IN_DB, REFUSED, UNREADABLE = "advisory-not-in-db", "refused", "unreadable"
CONVERTED = {MIGRATED}

# the syft vulnerability-match-labels' .yardstick.yaml pinned from each commit on, from
# `git log -- .yardstick.yaml` on its main branch. None is the three days it was pinned to latest.
# The repository is retired once ported, so the table is closed.
SYFT_PINS = [
    (datetime.fromisoformat(at), version)
    for at, version in [
        ("2022-09-26T16:25:23-04:00", "v0.54.0"),  # f8bcb08e
        ("2022-11-01T16:28:03-04:00", "v0.60.1"),  # ee718585
        ("2023-01-25T17:36:08-05:00", "v0.68.1"),  # 76468b93
        ("2023-03-02T15:07:09-05:00", "v0.74.0"),  # e60f872f
        ("2023-03-10T05:20:17+00:00", None),  # 660cb72c
        ("2023-03-13T19:05:11+00:00", "v0.74.1"),  # 27017236
        ("2023-08-04T19:47:53+00:00", "v0.86.1"),  # b2b84168
        ("2023-08-18T06:09:52-04:00", "v0.87.1"),  # d5a387f2
        ("2023-09-06T17:26:51+00:00", "v0.89.0"),  # c12c277e
        ("2023-11-30T09:25:56-05:00", "v0.98.0"),  # bf48f5d9
        ("2024-10-14T17:01:56+00:00", "v1.14.0"),  # 8915ebaa
    ]
]


def syft_at(at):
    """Return the syft pinned when a call was made, None before the first pin or while it was latest."""
    version = None
    for since, v in SYFT_PINS:
        if since > at:
            break
        version = v
    return version


def parse_tool(s):
    """Return (name, version) for a tool as vulnerability-match-labels wrote it.

    grype[custom-db]@v0.77.4 is grype v0.77.4 and grype@v0.63.1+profile=cpe is grype v0.63.1:
    the variant and metadata were yardstick's own markers, kept by the note that carries the
    string whole.
    """
    name, at, version = (s or "").partition("@")
    if not at:
        return "", ""
    return name.split("[", 1)[0], version.split("+", 1)[0]


def seen_tools(tool, at):
    """Return the seenIn tools of one call: the tool it names and, for grype or no tool, the syft pinned then."""
    out = []
    name, version = parse_tool(tool)
    if name and version:
        out.append({"name": name, "version": version})
    if name in ("", "grype") and (syft := syft_at(at)):
        out.append({"name": "syft", "version": syft})
    return out


def parse_time(s):
    """Return a timestamp as an aware UTC datetime; one without an offset is UTC."""
    t = datetime.fromisoformat(s.strip().replace(" ", "T", 1) if len(s.strip()) > 10 else s.strip())
    return (t if t.tzinfo else t.replace(tzinfo=UTC)).astimezone(UTC)


def rfc3339(t):
    return t.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Vocabulary:
    advisory_ids: list
    namespaces: list

    @classmethod
    def read(cls, path):
        # the two flow lists conversion needs; there is no YAML parser in the standard library
        text = Path(path).read_text()

        def flow(key):
            m = re.search(rf"^{key}:\s*\[(.*)\]\s*$", text, re.MULTILINE)
            if not m:
                raise ValueError(f"{path}: no {key}: [...] line")
            return [v.strip().strip("\"'") for v in m.group(1).split(",") if v.strip()]

        return cls(flow("advisory-ids"), flow("vulnerability-namespaces"))

    def is_advisory(self, vid):
        ns = vid.split("-", 1)[0]
        return any(fnmatch.fnmatchcase(ns, p) for p in self.advisory_ids)

    def accepts(self, vid):
        """Say whether a label may name vid: a disclosure in an accepted namespace, or an advisory."""
        return self.is_advisory(vid) or vid.split("-", 1)[0] in self.namespaces


def label_purl(purl):
    """Return the purl a label names: type, namespace, name and version, plus the epoch qualifier.

    The version vulnerability-match-labels recorded carries the epoch; other qualifiers (arch,
    distro, upstream) are dropped so the label still pairs after an SBOM rebuild.
    """
    if not purl:
        return ""
    base, _, rest = purl.partition("?")
    quals = rest.split("#", 1)[0]
    base = base.split("#", 1)[0]
    epoch = [q for q in quals.split("&") if q.startswith("epoch=")]
    return base + ("?" + epoch[0] if epoch else "")


@dataclass
class SbomIndex:
    """An image SBOM's packages, by name@version, by lowercased name@version and by location."""

    by_name_version: dict = field(default_factory=dict)
    by_folded: dict = field(default_factory=dict)
    by_location: dict = field(default_factory=dict)
    platform: str = ""
    distro: str = ""  # <id>:<versionID>, as amzn:2

    @classmethod
    def read(cls, path, image_digest):
        doc = json.loads(Path(path).read_text())
        idx = cls()
        if d := doc.get("distro"):
            idx.distro = f"{d.get('id', '')}:{d.get('versionID', '')}"
        md = doc.get("source", {}).get("metadata", {})
        # an index digest's SBOM cataloged one platform of it, which the label file records
        if md.get("manifestDigest") and md["manifestDigest"] != image_digest and md.get("os"):
            idx.platform = "/".join(p for p in (md["os"], md.get("architecture", ""), md.get("variant", "")) if p)
        for a in doc.get("artifacts", []):
            ref = (a.get("type", ""), label_purl(a.get("purl", "")))
            key = f"{a.get('name')}@{a.get('version')}"
            for m, k in ((idx.by_name_version, key), (idx.by_folded, folded(a.get("name") or "", a.get("version")))):
                if ref not in m.setdefault(k, []):
                    m[k].append(ref)
            if not ref[1]:
                continue
            locs = [(a.get("metadata") or {}).get("virtualPath")] + [loc.get("path") for loc in a.get("locations") or []]
            for loc in filter(None, locs):
                if ref not in idx.by_location.setdefault(loc, []):
                    idx.by_location[loc].append(ref)
        return idx


def folded(name, version):
    return f"{name.lower()}@{version}"


def db_advisory(vid, distro):
    """Return the id grype's DB knows an advisory by, for one named on an image of distro.

    vulnerability-match-labels named Amazon Linux 2 advisories as grype then reported them:
    ALAS-2023-2197, ALASKERNEL-5.10-2022-005. grype's DB now names them ALAS2-2023-2197 and
    ALAS2KERNEL-5.10-2022-005, and holds none of the unprefixed ids. Amazon Linux 1 numbers its
    own advisories ALAS-..., so the rename is only for an Amazon Linux 2 image.
    """
    if distro == "amzn:2" and vid.startswith("ALAS") and not vid.startswith("ALAS2"):
        return "ALAS2" + vid[4:]
    return vid


def image_dir(repository, digest):
    return f"pkg/oci/{repository}/{digest.replace(':', '-', 1)}"


@dataclass
class Call:
    """One readable input label, with what was resolved for it."""

    entry: dict
    source: dict
    verdict: str
    at: datetime
    repository: str
    digest: str
    platform: str
    packages: list  # [(type, purl)]
    location: str = ""
    distro: str = ""

    @property
    def tools(self):
        return seen_tools(self.source.get("tool"), self.at)


VERDICTS = {"TP": "tp", "FP": "fp", "??": "unclear", "UNCLEAR": "unclear"}


def resolve(src, split_ref, sbom_for):
    """Return (Call, None) for a readable label whose package the image's SBOM holds, else (None, (outcome, reason)).

    split_ref turns an image reference into (repository, digest); sbom_for(repository, digest)
    returns that image's SbomIndex, or None when the corpus holds no SBOM for it.
    """
    verdict = VERDICTS.get((src.get("label") or "").upper())
    if verdict is None:
        return None, (UNREADABLE, f"label {src.get('label')!r} is not TP, FP or ??")
    if not src.get("vulnerability_id") or not (src.get("image") or {}).get("exact"):
        return None, (UNREADABLE, "a label needs a vulnerability_id and an image")
    try:
        at = parse_time(src.get("timestamp") or "")
    except ValueError as e:
        return None, (UNREADABLE, str(e))
    pkg = src.get("package") or {}
    fullentry = src.get("fullentry_fields") or []
    if not pkg.get("name") and not fullentry:
        return None, (NO_PACKAGE, "no package and no fullentry_fields to find one by")
    repository, digest = split_ref(src["image"]["exact"])
    idx = sbom_for(repository, digest)
    if idx is None:
        return None, (NO_SBOM, "the corpus holds no sbom.syft.json for the image, so its package type is unknown")
    call = Call(
        entry={}, source=src, verdict=verdict, at=at, repository=repository, digest=digest, platform=idx.platform, packages=[], distro=idx.distro
    )
    if not pkg.get("name"):
        # matched by the package's location; a location several packages share (an OS package
        # database) says nothing about which one, so it places nothing
        for loc in fullentry:
            found = idx.by_location.get(loc, [])
            if len(found) == 1:
                call.packages, call.location = found, loc
                return call, None
        return None, (NO_PACKAGE, f"no single package in the image's SBOM at {' or '.join(fullentry)}")
    # labels were made against SBOMs from many syft versions, and syft has changed the case of some
    # names (pyOpenSSL is pyopenssl), so case alone does not lose a package
    found = idx.by_name_version.get(f"{pkg['name']}@{pkg.get('version')}") or idx.by_folded.get(folded(pkg["name"], pkg.get("version")), [])
    if not found:
        return None, (NOT_IN_SBOM, f"no package {pkg['name']} at version {pkg.get('version')} in the image's SBOM")
    call.packages = [p for p in found if p[1]]
    if not call.packages:
        return None, (NO_PURL, f"the image's SBOM has {pkg['name']} at {pkg.get('version')} with no purl to name it by")
    return call, None


def note_for(call, vuln):
    """Return one call as a note by its labeler at its time."""
    src = call.source
    text = f"ported from vulnerability-match-labels {src.get('ID', '')}: {call.verdict}"
    if (named := src.get("vulnerability_id")) != vuln:
        text += f" on {named}, which grype's DB now names {vuln}"
    if call.location:
        text += f" on the package at {call.location}"
    if src.get("tool"):
        text += f" with {src['tool']}"
    if src.get("note"):
        text += f". {src['note']}"
    return {"text": text, "author": src.get("user") or "unknown", "at": rfc3339(call.at)}


def merge(purl, vuln, contributions):
    """Return the one corpus label for a key from every call on it.

    Calls that disagree become one unclear label, each call's verdict kept in its note.
    """
    calls = contributions
    verdicts = {c.verdict for c in calls}
    label = {"package": purl, "vulnerability": vuln}
    if len(verdicts) > 1:
        label["verdict"], label["justification"] = "unclear", LABELERS_DISAGREE
    else:
        label["verdict"] = calls[0].verdict
        if label["verdict"] != "tp":
            label["justification"] = NOT_RECORDED
    label["author"] = ", ".join(sorted({c.source.get("user") or "unknown" for c in calls}))
    label["notes"] = sorted((note_for(c, vuln) for c in calls), key=lambda n: (n["at"], n["text"]))
    # seenIn is what the latest call that says anything was made against
    seen = [c for c in calls if c.tools]
    if seen:
        label["seenIn"] = {"tools": max(seen, key=lambda c: c.at).tools}
    label["firstIssued"] = rfc3339(min(c.at for c in calls))
    label["lastUpdated"] = rfc3339(max(c.at for c in calls))
    return label


def convert(records, vocab, split_ref, sbom_for, lookup):
    """Return ({file path: label file}, [report entry]) for every input label.

    records are (source path, label) pairs; lookup(advisory ids) returns {advisory: [aliases]} for
    those grype's DB holds.
    """
    entries, calls, advisories = [], [], set()
    for path, src in records:
        pkg = src.get("package") or {}
        e = {
            "source": path,
            "id": src.get("ID", ""),
            "image": (src.get("image") or {}).get("exact", ""),
            "package": f"{pkg['name']}@{pkg.get('version')}" if pkg.get("name") else "",
            "vulnerability": src.get("vulnerability_id", ""),
            "verdict": src.get("label", ""),
        }
        entries.append(e)
        call, why = resolve(src, split_ref, sbom_for)
        if why:
            e["outcome"], e["reason"] = why
            continue
        call.entry, e["outcome"] = e, MIGRATED
        calls.append(call)
        if vocab.is_advisory(e["vulnerability"]):
            advisories.add(db_advisory(e["vulnerability"], call.distro))

    # only whether the DB holds the id matters: the label stays on the advisory
    known = set(lookup(sorted(advisories))) if advisories else set()

    by_key = {}
    for c in calls:
        e, vid = c.entry, c.entry["vulnerability"]
        if vocab.is_advisory(vid):
            vid = e["named"] = db_advisory(vid, c.distro)
            if vid not in known:
                e["outcome"], e["reason"] = NOT_IN_DB, f"grype's DB has no {vid}, so the id grype reports for it today is unknown"
                continue
        elif not vocab.accepts(vid):
            e["outcome"], e["reason"] = REFUSED, f"{vid} is in no namespace vocabulary.yaml accepts"
            continue
        for typ, purl in c.packages:
            by_key.setdefault((image_dir(c.repository, c.digest), typ, purl, vid), []).append(c)

    files = {}
    for (d, typ, purl, vid), cs in sorted(by_key.items()):
        c = cs[0]
        f = files.setdefault(
            f"{d}/{MATCHES}/{typ}.json", {"schema": SCHEMA_VERSION, "subject": {"image": f"{c.repository}@{c.digest}"}, "labels": []}
        )
        if c.platform:
            f["subject"]["platform"] = c.platform
        label = merge(purl, vid, cs)
        f["labels"].append(label)
        for call in cs:
            call.entry.setdefault("became", []).append(
                {"file": f"{d}/{MATCHES}/{typ}.json", "package": purl, "vulnerability": vid, "verdict": label["verdict"]}
            )
    for f in files.values():
        f["labels"].sort(key=lambda lb: (lb.get("package", ""), lb["vulnerability"]))
    return files, entries


def marshal(f):
    """Encode a label file the way yardstick's writer does: two-space indent, no escaping, a trailing newline."""
    return json.dumps(f, indent=2, ensure_ascii=False) + "\n"


def parse_grype_search(data):
    """Return {id: [aliases]} from `grype db search vuln <id>... -o json`."""
    out = {}
    for r in json.loads(data or "[]"):
        out.setdefault(r["id"], []).extend(r.get("aliases") or [])
    return out


# a note the port wrote when it moved an advisory's call to a CVE, before advisory labels kept the
# advisory: "...: tp on AVG-2845, which names 2 CVEs; not assessed for this one"
DEREFERENCED = re.compile(
    r"^ported from vulnerability-match-labels (?P<id>\S+): (?P<verdict>\w+) on (?P<advisory>\S+)(?: \(\S+ in grype's DB\))?, "
    r"which names (?:only (?P<only>\S+)|(?P<n>\d+) CVEs; not assessed for this one)"
)
PORTED = "ported from vulnerability-match-labels "


def dereferenced(label):
    """Return the notes of label that say the port moved an advisory's call to it."""
    return [m for n in label.get("notes") or [] if (m := DEREFERENCED.match(n.get("text", "")))]


def ported_only(label):
    """Say whether every note on label is one the port wrote, so nobody has added to it since."""
    notes = label.get("notes") or []
    return bool(notes) and all(n.get("text", "").startswith(PORTED) for n in notes)


def reconcile(old, new):
    """Return (labels, changes): a label file's committed labels (old) with the port's (new) folded in.

    Only a label the port made from dereferencing an advisory is replaced, by whatever the port now
    writes for its key (nothing, for a call that stays on its advisory). Every other committed label
    stays as it is: one somebody added to or wrote is listed as kept, and one the port made from a
    CVE or GHSA call that the port would now write differently is listed as differs.
    """
    key = lambda lb: (lb.get("package", ""), lb["vulnerability"])
    fresh = {key(lb): lb for lb in new}
    changes = {"removed": [], "added": [], "kept": [], "differs": []}
    out = {}
    for lb in old:
        if not ported_only(lb):
            changes["kept"].append(lb)
        elif dereferenced(lb):
            changes["removed"].append(lb)
            continue
        elif fresh.get(key(lb)) != lb:
            changes["differs"].append(lb)
        out[key(lb)] = lb
    for k, lb in fresh.items():
        if k not in out:
            out[k] = lb
            changes["added"].append(lb)
    return sorted(out.values(), key=key), changes
