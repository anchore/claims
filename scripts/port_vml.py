#!/usr/bin/env python3
"""Port labels from anchore/vulnerability-match-labels into this claims corpus.

- images labeled as docker.io/anchore/test_images are moved to their ghcr.io/anchore/test-images
  mirror (same digest, see anchore/test-images#89), when that mirror exists
- each image's sbom.syft.json comes from R2 as sboms.py fetches it, else from the SBOMs
  vulnerability-match-labels publishes when built with the syft catalog.yaml pins, else is built
  with `yardstick collect sboms`, since a label's package type and purl come from the SBOM
- labels are converted by vml_convert.py, with grype's DB saying which advisory ids it holds

  port_vml.py status [--vml DIR]       read-only summary of how far the port has got
  port_vml.py advisories [--vml DIR]   read-only report of the labels an earlier port made by moving
                                       advisories to CVEs, the advisory labels they should be, and
                                       the advisory ids grype's DB lacks
  port_vml.py port [--vml DIR]         download or build missing SBOMs, then convert every label

Rerunning port is safe: SBOMs already in the corpus are not rebuilt, and the same labels give the
same files. A label an earlier port moved from an advisory to a CVE is replaced; every other label
already in the corpus is kept as it is, and listed when the port would now write it differently or
somebody has added to it.
"""

import argparse
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import sboms
import vml_convert
from sboms import Abort, catalog_syft

CORPUS = Path(__file__).resolve().parent.parent
TEST_IMAGES_HUB = "docker.io/anchore/test_images"
TEST_IMAGES_GHCR = "ghcr.io/anchore/test-images"
HUB_TAGS_URL = "https://hub.docker.com/v2/namespaces/anchore/repositories/test_images/tags?page_size=100"
DEFAULT_REPORT = Path(tempfile.gettempdir()) / "match-claims-port"
VML_SBOMS = "ghcr.io/anchore/vml-sbom"

# a truncated Docker Hub listing must not read as "nothing is mirrored". It held 885 tags when
# this was written and only grows.
MIN_HUB_TAGS = 800

# a private package answers anonymous reads with UNAUTHORIZED/DENIED, which is "not mirrored" too
NOT_FOUND_RE = re.compile(r"MANIFEST_UNKNOWN|NAME_UNKNOWN|UNAUTHORIZED|DENIED|not found|404", re.IGNORECASE)


def split_ref(exact):
    """Return (repository, digest) for an image reference, with docker's defaults applied.

    'anchore/test_images@sha256:..' is ('docker.io/anchore/test_images', 'sha256:..') and
    'docker.io/postgres:13.2@sha256:..' is ('docker.io/library/postgres', 'sha256:..').
    """
    name, _, digest = exact.partition("@")
    first, _, rest = name.partition("/")
    if not rest or not ("." in first or ":" in first or first == "localhost"):
        first, rest = "docker.io", name
    if first == "docker.io" and "/" not in rest:
        rest = "library/" + rest
    # a tag is a ':' after the last '/'; a ':' before it is a registry port
    head, _, last = rest.rpartition("/")
    rest = f"{head}/{last.split(':', 1)[0]}" if head else last.split(":", 1)[0]
    return f"{first}/{rest}", digest


def ghcr_ref(tag, digest):
    """Return the ghcr mirror of a test_images tag, or None for a tag the mirror skips.

    The mirror takes '<dir>-<7 hex sha>' to ghcr.io/anchore/test-images/<dir>:<sha>, splitting
    on the last '-'. Pre-sha and vendor tags were never mirrored.
    """
    image, _, sha = tag.rpartition("-")
    if not image or len(sha) != 7 or any(c not in "0123456789abcdef" for c in sha):
        return None
    return f"{TEST_IMAGES_GHCR}/{image}:{sha}@{digest}"


def hub_tags_by_digest():
    """Return {digest: [tag, ...]} for docker.io/anchore/test_images, by index and per-platform digest."""
    out, url, n = {}, HUB_TAGS_URL, 0
    while url:
        # curl rather than urllib: python.org builds on macOS ship without a CA bundle
        res = subprocess.run(["curl", "-fsSL", "--max-time", "60", url], capture_output=True, text=True, check=False)
        if res.returncode != 0:
            raise Abort(f"listing Docker Hub tags failed: {res.stderr.strip()}")
        page = json.loads(res.stdout)
        for t in page["results"]:
            n += 1
            for d in {t.get("digest"), *(i.get("digest") for i in t.get("images") or [])}:
                if d:
                    out.setdefault(d, []).append(t["name"])
        url = page.get("next")
    if n < MIN_HUB_TAGS:
        raise Abort(f"Docker Hub listed {n} test_images tags, expected at least {MIN_HUB_TAGS}; refusing to plan from a truncated listing")
    return out


def crane(*args):
    """Run crane anonymously, returning (stdout, None), or (None, stderr) for a ref that is not there."""
    # an empty docker config, so a credential cannot make a private package look public
    with tempfile.TemporaryDirectory() as empty:
        try:
            res = subprocess.run(["crane", *args], capture_output=True, env={**os.environ, "DOCKER_CONFIG": empty}, check=False)
        except FileNotFoundError:
            raise Abort("crane is not on PATH")
    if res.returncode == 0:
        return res.stdout, None
    stderr = res.stderr.decode(errors="replace").strip()
    if NOT_FOUND_RE.search(stderr):
        return None, stderr
    # anything else (rate limit, network) must not read as "not there"
    raise Abort(f"crane {' '.join(args)} failed:\n{stderr}")


def exists(ref):
    """Say whether ref is readable anonymously, which is what every consumer of the corpus gets."""
    return crane("digest", ref)[0] is not None


def vml_sbom_ref(exact):
    """Return where vulnerability-match-labels published the SBOM of an image its labels name.

    It is keyed by the image as vulnerability-match-labels wrote it, with docker.io added but no
    library/: docker.io/alpine@sha256:.. is ghcr.io/anchore/vml-sbom/docker.io/alpine:sha256-..
    """
    name, _, digest = exact.partition("@")
    first, _, rest = name.partition("/")
    if not rest or not ("." in first or ":" in first or first == "localhost"):
        name = "docker.io/" + name
    head, _, last = name.rpartition("/")
    return f"{VML_SBOMS}/{head}/{last.split(':', 1)[0]}:{digest.replace(':', '-', 1)}"


def download_sbom(exact, want):
    """Return the SBOM vulnerability-match-labels published for an image, or None when there is none
    or it was built with another syft than want."""
    ref = vml_sbom_ref(exact)
    manifest, _ = crane("manifest", ref)
    if manifest is None:
        return None
    layers = [l for l in json.loads(manifest)["layers"] if l.get("annotations", {}).get("org.opencontainers.image.title") == "data.json"]
    if len(layers) != 1:
        return None
    data, err = crane("blob", f"{ref.rpartition(':')[0]}@{layers[0]['digest']}")
    if data is None:
        raise Abort(f"{ref} names a data.json it does not hold: {err}")
    version = json.loads(data).get("descriptor", {}).get("version")
    return data if want and version == want else None


def read_vml(vml, only=None):
    """Return {image dir: [(file name, [label, ...]), ...]} from a vulnerability-match-labels checkout."""
    root = vml / "labels"
    if not root.is_dir():
        raise Abort(f"{root} is not a directory; --vml is a vulnerability-match-labels checkout")
    out = {}
    for d in sorted(p for p in root.iterdir() if p.is_dir()):
        if only and not any(fnmatch.fnmatch(d.name, g) for g in only):
            continue
        files = []
        for f in sorted(d.glob("*.json")):
            dec, text, i, labels = json.JSONDecoder(), f.read_text(), 0, []
            # a label file may hold several objects one after another
            while rest := text[i:].lstrip():
                obj, i = dec.raw_decode(text, len(text) - len(rest))
                labels.append(obj)
            files.append((f.name, labels))
        out[d.name] = files
    return out


def plan(vml_images):
    """Return {image exact: target ref} for every image the labels name.

    A test_images image becomes its ghcr mirror when one of its tags is mirrored there. Every
    other image keeps its reference.
    """
    exacts = sorted({l["image"]["exact"] for files in vml_images.values() for _, ls in files for l in ls})
    hub = None
    out = {}
    for exact in exacts:
        repo, digest = split_ref(exact)
        out[exact] = exact
        if repo != TEST_IMAGES_HUB:
            continue
        if hub is None:
            hub = hub_tags_by_digest()
        for tag in sorted(hub.get(digest, [])):
            ref = ghcr_ref(tag, digest)
            if ref and exists(ref):
                out[exact] = ref
                break
    return out


def corpus_state():
    """Return ({image dir with an SBOM}, {image dir: label count}, [stale image dir]) for what the corpus holds.

    Image directories rather than digests, since two repositories can share a digest. An SBOM
    built by another syft than catalog.yaml pins is stale: it is left out of the first set, so
    port rebuilds it.
    """
    want = catalog_syft()
    sboms, counts, stale = set(), {}, []
    for f in (CORPUS / "pkg" / "oci").rglob("*.json"):
        d = f.parent.relative_to(CORPUS).as_posix()
        if f.name == "sbom.syft.json":
            if want and json.loads(f.read_text())["descriptor"]["version"] != want:
                stale.append(d)
            else:
                sboms.add(d)
        else:
            counts[d] = counts.get(d, 0) + len(json.loads(f.read_text()).get("labels", []))
    return sboms, counts, sorted(stale)


def vml_head(vml):
    res = subprocess.run(["git", "-C", str(vml), "describe", "--always", "--dirty", "--all", "--long"], capture_output=True, text=True, check=False)
    return res.stdout.strip() or "unknown"


def cmd_status(args):
    images = read_vml(args.vml, args.only)
    targets = plan(images)
    sboms, counts, stale_sboms = corpus_state()

    print(f"vulnerability-match-labels: {args.vml} ({vml_head(args.vml)})")
    print(f"corpus: {CORPUS}\n")
    print(f"{'image':<80} {'sbom':<4} {'vml':>5} {'claims':>6}")
    done = 0
    vml_total = claims_total = 0
    for d, files in images.items():
        n = sum(len(ls) for _, ls in files)
        exact = files[0][1][0]["image"]["exact"] if files and files[0][1] else d
        repo, digest = split_ref(targets.get(exact, exact))
        have, c = vml_convert.image_dir(repo, digest) in sboms, counts.get(vml_convert.image_dir(repo, digest), 0)
        done += have and c > 0
        vml_total += n
        claims_total += c
        print(f"{repo + '@' + digest[7:19]:<80} {'yes' if have else '-':<4} {n:>5} {c:>6}")

    hub = [e for e, t in targets.items() if split_ref(t)[0] == TEST_IMAGES_HUB]
    moved = [e for e, t in targets.items() if t != e]
    print(f"\nimages: {len(images)}, ported: {done}, remaining: {len(images) - done}")
    print(
        f"labels: {vml_total} in vulnerability-match-labels, {claims_total} in the corpus (disagreements merge and a label is per purl, so these differ)"
    )
    print(f"test_images moved to ghcr: {len(moved)}, left on Docker Hub (not mirrored): {len(hub)}")
    for e in hub:
        print(f"  {e}")

    if stale_sboms:
        print(f"\nSBOMs built with another syft than catalog.yaml pins (syft {catalog_syft()}), which port rebuilds:")
        for v in stale_sboms:
            print(f"  {v}")

    # an image left on Docker Hub belongs there; anything else under it should have moved
    kept = {split_ref(e)[1].replace(":", "-", 1) for e in hub}
    stale = sorted(v for v in [*sboms, *stale_sboms] if v.startswith(f"pkg/oci/{TEST_IMAGES_HUB}/") and v.rsplit("/", 1)[1] not in kept)
    if stale:
        print(f"\ncorpus images still under {TEST_IMAGES_HUB}:")
        for v in stale:
            print(f"  {v}")

    report = args.report / "report.json"
    if report.exists():
        entries = json.loads(report.read_text())
        outcomes = {}
        for e in entries:
            outcomes[e["outcome"]] = outcomes.get(e["outcome"], 0) + 1
        print(f"\nlast port report ({report}):")
        for o, n in sorted(outcomes.items()):
            print(f"  {o:<22} {n}")
    return 0


def convert_images(args, images, targets):
    """Return (files, entries): every label of images converted, against the SBOMs the corpus holds."""
    vocab = vml_convert.Vocabulary.read(CORPUS / "vocabulary.yaml")
    records = []
    for d, files in images.items():
        for name, labels in files:
            for label in labels:
                label["image"]["exact"] = targets[label["image"]["exact"]]
                records.append((f"{d}/{name}", label))

    have_sboms, _, _ = corpus_state()
    cache = {}

    def sbom_for(repository, digest):
        d = vml_convert.image_dir(repository, digest)
        if d not in cache:
            cache[d] = vml_convert.SbomIndex.read(CORPUS / d / "sbom.syft.json", digest) if d in have_sboms else None
        return cache[d]

    def lookup(ids):
        print(f"looking up {len(ids)} advisories with {args.grype}", flush=True)
        res = subprocess.run(
            [args.grype, "db", "search", "vuln", "--limit", "0", "-o", "json", "-q", *ids], capture_output=True, text=True, check=False
        )
        if res.returncode != 0:
            raise Abort(f"grype db search failed:\n{res.stderr.strip()}")
        return vml_convert.parse_grype_search(res.stdout)

    print(f"\nconverting {len(records)} labels on {len(images)} images from {args.vml} ({vml_head(args.vml)})", flush=True)
    return vml_convert.convert(records, vocab, split_ref, sbom_for, lookup)


def reconciled(targets, files):
    """Return {image dir: {file: (label file or None to remove it, changes)}} for every ported image.

    Each image's committed label files are folded together with what the port converted, so only
    the labels an earlier port moved from an advisory to a CVE are replaced.
    """
    out = {}
    for target in sorted(set(targets.values())):
        d = vml_convert.image_dir(*split_ref(target))
        old = {f"{d}/{p.name}": json.loads(p.read_text()) for p in sorted((CORPUS / d).glob("*.json")) if p.name != "sbom.syft.json"}
        new = {rel: f for rel, f in files.items() if rel.startswith(d + "/")}
        written = {}
        for rel in sorted({*old, *new}):
            base = new.get(rel) or old[rel]
            labels, ch = vml_convert.reconcile(old.get(rel, {}).get("labels", []), new.get(rel, {}).get("labels", []))
            written[rel] = ({**base, "labels": labels} if labels else None, ch)
        out[d] = written
    return out


def print_kept(changes):
    """Print the committed labels the port left alone although it would not write them so.

    changes is [(file, reconcile's changes)].
    """
    for what, why in (("kept", "somebody added to them since the port"), ("differs", "the port would now write them differently")):
        rows = [(rel, lb) for rel, ch in changes for lb in ch[what]]
        if rows:
            print(f"\n{len(rows)} labels kept as committed, since {why}:")
            for rel, lb in rows:
                print(f"  {rel}: {lb.get('package', '')} {lb['vulnerability']} {lb['verdict']}")


def cmd_advisories(args):
    """Report the labels the advisory-dereferencing port made, what they should be, and the ids the DB lacks."""
    images = read_vml(args.vml, args.only)
    # only the label directories that hold an advisory call, unless --only picked them
    vocab = vml_convert.Vocabulary.read(CORPUS / "vocabulary.yaml")
    if not args.only:
        images = {d: fs for d, fs in images.items() if any(vocab.is_advisory(lb.get("vulnerability_id", "")) for _, ls in fs for lb in ls)}
    by_id = {lb.get("ID"): lb for fs in images.values() for _, ls in fs for lb in ls}
    targets = plan(images)
    files, entries = convert_images(args, images, targets)
    done = reconciled(targets, files)

    def verdicts(labels):
        n = {}
        for lb in labels:
            n[lb["verdict"]] = n.get(lb["verdict"], 0) + 1
        return " ".join(f"{v} {n[v]}" for v in ("tp", "fp", "unclear") if v in n) or "-"

    total = {"removed": [], "added": [], "present": [], "missing": set(), "unported": 0, "mismatch": []}
    changes = [(rel, ch) for out in done.values() for rel, (_, ch) in out.items()]
    for d, out in done.items():
        removed = [lb for _, ch in out.values() for lb in ch["removed"]]
        added = [lb for _, ch in out.values() for lb in ch["added"]]
        advisory = [lb for lb in added if vocab.is_advisory(lb["vulnerability"])]
        present = [lb for f, _ in out.values() if f for lb in f["labels"] if vocab.is_advisory(lb["vulnerability"])]
        total["present"] += present
        # an advisory call the port could not write: the DB lacks its id, or its package is not in the SBOM
        mine = [e for e in entries if vocab.is_advisory(e["vulnerability"]) and vml_convert.image_dir(*split_ref(e["image"])) == d]
        missing = sorted({e["named"] for e in mine if e["outcome"] == vml_convert.NOT_IN_DB})
        unported = [e for e in mine if e["outcome"] not in vml_convert.CONVERTED]
        # each removed label's note names the call it came from, which must be an advisory call in vulnerability-match-labels
        mismatch = [
            (lb["vulnerability"], m["id"])
            for lb in removed
            for m in vml_convert.dereferenced(lb)
            if (by_id.get(m["id"]) or {}).get("vulnerability_id") != m["advisory"]
        ]
        single = [lb for lb in removed if all(m["only"] for m in vml_convert.dereferenced(lb))]
        if not (removed or mine):
            continue
        print(f"\n{d}")
        print(f"  CVE labels moved from an advisory, to remove: {len(removed)} ({verdicts(removed)})")
        print(f"    from single-CVE advisories {len(single)}, multi-CVE {len(removed) - len(single)}; vml cross-check mismatches {len(mismatch)}")
        print(f"  vml advisory calls: {len(mine)}, ported {len(mine) - len(unported)}")
        print(f"  advisory labels to add: {len(advisory)} ({verdicts(advisory)}), already in the corpus: {len(present) - len(advisory)}")
        other = [lb for lb in added if not vocab.is_advisory(lb["vulnerability"])]
        if other:
            print(f"  CVE labels rewritten from their own calls (were merged with an advisory's): {len(other)} ({verdicts(other)})")
        for o in sorted({e["outcome"] for e in unported}):
            print(f"  advisory calls not ported, {o}: {sum(e['outcome'] == o for e in unported)}")
        if missing:
            print(f"  not in grype's DB: {', '.join(missing)}")
        for k, v in (("removed", removed), ("added", added), ("mismatch", mismatch)):
            total[k] += v
        total["missing"] |= set(missing)
        total["unported"] += len(unported)

    print("\noverall")
    print(f"  CVE labels moved from an advisory, to remove: {len(total['removed'])} ({verdicts(total['removed'])})")
    print(f"  vml cross-check mismatches: {len(total['mismatch'])} {total['mismatch'] or ''}")
    added = [lb for lb in total["added"] if vocab.is_advisory(lb["vulnerability"])]
    print(f"  advisory labels to add: {len(added)} ({verdicts(added)}), already in the corpus: {len(total['present']) - len(added)}")
    print(f"  advisory calls not ported: {total['unported']}")
    print(f"  not in grype's DB: {', '.join(sorted(total['missing'])) or '-'}")
    print_kept(changes)
    # labels moved from an advisory anywhere in the corpus, so none hides outside the label directories read
    elsewhere = sorted(
        f.parent.relative_to(CORPUS).as_posix()
        for f in (CORPUS / "pkg").rglob("*.json")
        if f.name != "sbom.syft.json"
        and f.parent.relative_to(CORPUS).as_posix() not in done
        and any(vml_convert.dereferenced(lb) for lb in json.loads(f.read_text()).get("labels", []))
    )
    print(f"  image directories outside these with labels moved from an advisory: {len(elsewhere)}")
    for d in elsewhere:
        print(f"    {d}")
    return 0


def cmd_port(args):
    for tool in (args.yardstick, args.grype):
        if not Path(tool).exists() and not shutil.which(tool):
            raise Abort(f"{tool} not found; run `make tools` to install the pinned tools")
    for f in ("vocabulary.yaml", "catalog.yaml"):
        if not (CORPUS / f).exists():
            raise Abort(f"{CORPUS / f} is missing; conversion and collect sboms need it")
    images = read_vml(args.vml, args.only)
    if not images:
        raise Abort("no label directories matched")
    targets = plan(images)

    want, failed, have = catalog_syft(), [], set()
    # vulnerability-match-labels keyed its SBOMs by the image as the labels name it, so that is
    # what the fallback looks up. Each image directory needs its own SBOM, even where two
    # repositories share a digest.
    for exact, target in sorted(targets.items()):
        d = vml_convert.image_dir(*split_ref(target))
        if d in have:
            continue
        have.add(d)
        how = sboms.ensure(d, args.yardstick, fallback=lambda e=exact: download_sbom(e, want))
        if how == "failed":
            failed.append(target)
        elif how != "have":
            print(f"{how} the SBOM for {target}", flush=True)
    if failed:
        # their labels are reported as no-sbom, so keep going and let the report say so
        print(f"\n{len(failed)} SBOMs could not be built:", file=sys.stderr)
        for t in failed:
            print(f"  {t}", file=sys.stderr)

    files, entries = convert_images(args, images, targets)
    changes, written = [], 0
    for d, out in reconciled(targets, files).items():
        for rel, (f, ch) in out.items():
            if f is None:
                (CORPUS / rel).unlink()
            else:
                (CORPUS / rel).parent.mkdir(parents=True, exist_ok=True)
                (CORPUS / rel).write_text(vml_convert.marshal(f))
                written += len(f["labels"])
            changes.append((rel, ch))
    print_kept(changes)

    args.report.mkdir(parents=True, exist_ok=True)
    unknown = [e for e in entries if e["outcome"] not in vml_convert.CONVERTED]
    for name, data in (("report.json", entries), ("unknown.json", unknown)):
        (args.report / name).write_text(json.dumps(data, indent=2) + "\n")
    counts = {}
    for e in entries:
        counts[e["outcome"]] = counts.get(e["outcome"], 0) + 1
    print(f"{len(entries)} input labels:")
    for o, n in sorted(counts.items()):
        print(f"  {o:<22} {n}")
    print(
        f"converted {sum(len(f['labels']) for f in files.values())} labels and wrote {written}; labels not converted are in {args.report / 'unknown.json'}"
    )
    return 1 if failed else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--vml",
        type=Path,
        default=os.environ.get("VML") or CORPUS.parent / "vulnerability-match-labels",
        help="a vulnerability-match-labels checkout (default: $VML, else a sibling of this repo)",
    )
    parser.add_argument("--only", action="append", help="port only label directories matching this glob, e.g. 'anchore+test_images@*' (repeatable)")
    parser.add_argument(
        "--report",
        type=Path,
        default=DEFAULT_REPORT,
        help=f"where port writes report.json and unknown.json, outside the corpus (default: {DEFAULT_REPORT})",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="read-only summary of the port").set_defaults(fn=cmd_status)
    grype = argparse.ArgumentParser(add_help=False)
    grype.add_argument(
        "--grype", default=str(CORPUS / ".tool" / "grype"), help="the grype whose DB says which advisory ids exist (default: the pinned one)"
    )
    sub.add_parser(
        "advisories", parents=[grype], help="read-only report of labels moved from advisories to CVEs, and what they should be"
    ).set_defaults(fn=cmd_advisories)
    port = sub.add_parser("port", parents=[grype], help="download or build missing SBOMs and convert every label")
    port.add_argument(
        "--yardstick", default=str(CORPUS / ".tool" / "yardstick"), help="the yardstick binary (default: the one .binny.yaml pins, from `make tools`)"
    )
    port.set_defaults(fn=cmd_port)
    args = parser.parse_args(argv)
    args.vml, args.report = args.vml.resolve(), args.report.resolve()
    try:
        return args.fn(args)
    except Abort as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
