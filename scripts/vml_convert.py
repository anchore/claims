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
- an advisory id (by vocabulary.yaml's advisory-ids) moves to the CVEs grype's DB says it names: a
  call on an advisory naming one CVE moves with its verdict, one naming several becomes unclear
  (not-assessed) on each

What does not: effective_cve, and an image's tag (labels name images by digest).
"""

import fnmatch
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

# justifications this conversion writes; vocabulary.yaml defines them
NOT_RECORDED = "not-recorded"
LABELERS_DISAGREE = "labelers-disagree"
NOT_ASSESSED = "not-assessed"

# outcomes: the first three wrote labels
MIGRATED, CARRIED, FANNED_OUT = "migrated", "advisory-carried", "advisory-fanned-out"
NO_PACKAGE, NO_SBOM, NOT_IN_SBOM, NO_PURL = "no-package", "no-sbom", "package-not-in-sbom", "package-has-no-purl"
NO_CVE, REFUSED, UNREADABLE = "advisory-names-no-cve", "refused", "unreadable"
CONVERTED = {MIGRATED, CARRIED, FANNED_OUT}

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
        """Say whether a label may name vid: a disclosure in an accepted namespace."""
        return not self.is_advisory(vid) and vid.split("-", 1)[0] in self.namespaces


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

    @classmethod
    def read(cls, path, image_digest):
        doc = json.loads(Path(path).read_text())
        idx = cls()
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
    call = Call(entry={}, source=src, verdict=verdict, at=at, repository=repository, digest=digest, platform=idx.platform, packages=[])
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


def note_for(call, via, direct, cves, vuln):
    """Return one call as a note by its labeler at its time."""
    src = call.source
    text = f"ported from vulnerability-match-labels {src.get('ID', '')}: {call.verdict}"
    if via and direct:
        text += f" on {via}, which names only {vuln}"
    elif via:
        text += f" on {via}, which names {cves} CVEs; not assessed for this one"
    if call.location:
        text += f" on the package at {call.location}"
    if src.get("tool"):
        text += f" with {src['tool']}"
    if src.get("note"):
        text += f". {src['note']}"
    return {"text": text, "author": src.get("user") or "unknown", "at": rfc3339(call.at)}


def merge(purl, vuln, contributions):
    """Return the one corpus label for a key from every call on it.

    Direct calls win over calls fanned out from a multi-CVE advisory; direct calls that disagree
    become one unclear label, each call's verdict kept in its note.
    """
    direct = [c for c in contributions if c[1]]
    use = direct or contributions
    calls = [c[0] for c in use]
    verdicts = {c.verdict for c in calls}
    label = {"package": purl, "vulnerability": vuln}
    if not direct:
        label["verdict"], label["justification"] = "unclear", NOT_ASSESSED
    elif len(verdicts) > 1:
        label["verdict"], label["justification"] = "unclear", LABELERS_DISAGREE
    else:
        label["verdict"] = calls[0].verdict
        if label["verdict"] != "tp":
            label["justification"] = NOT_RECORDED
    label["author"] = ", ".join(sorted({c.source.get("user") or "unknown" for c in calls}))
    label["notes"] = sorted((note_for(c, via, d, n, vuln) for c, d, via, n in use), key=lambda n: (n["at"], n["text"]))
    # seenIn is what the latest call that says anything was made against
    seen = [c for c in calls if c.tools]
    if seen:
        label["seenIn"] = {"tools": max(seen, key=lambda c: c.at).tools}
    label["firstIssued"] = rfc3339(min(c.at for c in calls))
    label["lastUpdated"] = rfc3339(max(c.at for c in calls))
    return label


def convert(records, vocab, split_ref, sbom_for, lookup):
    """Return ({file path: label file}, [report entry]) for every input label.

    records are (source path, label) pairs; lookup(advisory ids) returns {advisory: [aliases]}.
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
            advisories.add(e["vulnerability"])

    names = {}
    if advisories:
        got = lookup(sorted(advisories))
        for a in advisories:
            names[a] = sorted({x for x in got.get(a, []) if vocab.accepts(x)})

    by_key = {}
    for c in calls:
        e, vuln = c.entry, c.entry["vulnerability"]
        ids, via = [vuln], ""
        if vocab.is_advisory(vuln):
            via, ids = vuln, names[vuln]
            if not ids:
                e["outcome"], e["reason"] = NO_CVE, f"grype's DB names no CVE for {via}"
                continue
            e["outcome"] = CARRIED if len(ids) == 1 else FANNED_OUT
        elif not vocab.accepts(vuln):
            e["outcome"], e["reason"] = REFUSED, f"{vuln} is in no namespace vocabulary.yaml accepts"
            continue
        for typ, purl in c.packages:
            for vid in ids:
                key = (image_dir(c.repository, c.digest), typ, purl, vid)
                by_key.setdefault(key, []).append((c, len(ids) == 1, via, len(ids)))

    files = {}
    for (d, typ, purl, vid), cs in sorted(by_key.items()):
        c = cs[0][0]
        f = files.setdefault(f"{d}/{typ}.json", {"schema": "v1", "subject": {"image": f"{c.repository}@{c.digest}"}, "labels": []})
        if c.platform:
            f["subject"]["platform"] = c.platform
        label = merge(purl, vid, cs)
        f["labels"].append(label)
        for call, *_ in cs:
            call.entry.setdefault("became", []).append(
                {"file": f"{d}/{typ}.json", "package": purl, "vulnerability": vid, "verdict": label["verdict"]}
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
