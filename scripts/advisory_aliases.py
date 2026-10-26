#!/usr/bin/env python3
"""Give every advisory label in the corpus that has none its aliases (label format 1.0.1).

An advisory label's alias is the CVE grype --by-cve reports its match as, so the label pairs that
match too; the verdict stays on the advisory. Where the image's SBOM is fetched (`make sboms`) the
CVE is read off a --by-cve scan of it, since grype reports a match it merged from two records (a
binary rpm found directly and through its source rpm) under the lowest CVE rather than the DB's
first. Otherwise it is the DB's first (vml_convert.by_cve). An advisory naming no CVE gets none.

Nothing else in a label changes, lastUpdated included: aliases say how grype reports the match,
not what the call is. A file that changes is raised to the format that has aliases.

  advisory_aliases.py [--grype G]
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

import vml_convert
from sboms import MATCHES, SBOM

CORPUS = Path(__file__).resolve().parent.parent


def grype_json(grype, *args):
    res = subprocess.run([grype, *args, "-o", "json", "-q"], capture_output=True, text=True, check=False)
    if res.returncode != 0:
        sys.exit(f"grype {' '.join(args[:3])} failed:\n{res.stderr.strip()}")
    return res.stdout


def scanned(grype, sbom):
    """Return {(label purl, advisory): {CVE}} from a --by-cve scan of an SBOM."""
    out = {}
    for m in json.loads(grype_json(grype, f"sbom:{sbom}", "--by-cve"))["matches"]:
        if m["vulnerability"]["id"].startswith("CVE-"):
            for r in m.get("relatedVulnerabilities") or []:
                out.setdefault((vml_convert.label_purl(m["artifact"].get("purl", "")), r["id"]), set()).add(m["vulnerability"]["id"])
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--grype", default=str(CORPUS / ".tool" / "grype"), help="the grype to scan and search the DB with (default: the pinned one)")
    args = parser.parse_args(argv)
    vocab = vml_convert.Vocabulary.read(CORPUS / "vocabulary.yaml")

    paths = sorted(p for root in ("pkg", "sbom", "global") for p in (CORPUS / root).rglob(f"{MATCHES}/*.json"))
    docs = {p: json.loads(p.read_text()) for p in paths}
    todo = {p: [lb for lb in d["labels"] if vocab.is_advisory(lb["vulnerability"]) and not lb.get("aliases")] for p, d in docs.items()}
    todo = {p: lbs for p, lbs in todo.items() if lbs}
    ids = sorted({lb["vulnerability"] for lbs in todo.values() for lb in lbs})
    if not ids:
        print("every advisory label has its aliases")
        return 0
    db = vml_convert.parse_grype_search(grype_json(args.grype, "db", "search", "vuln", "--limit", "0", *ids))

    scans, none = {}, []
    for p, lbs in todo.items():
        sbom = p.parent.parent / SBOM
        if sbom not in scans:
            scans[sbom] = scanned(args.grype, sbom) if sbom.exists() else None
        seen, n = scans[sbom], {"scan": 0, "db": 0}
        for lb in lbs:
            vid = lb["vulnerability"]
            cves = (seen or {}).get((lb["package"], vid), set())
            alias, how = (next(iter(cves)), "scan") if len(cves) == 1 else (vml_convert.by_cve(db.get(vid)), "db")
            if not alias:
                none.append(f"{p.relative_to(CORPUS)}: {lb['package']} {vid}")
                continue
            n[how] += 1
            # aliases sit right after vulnerability, as yardstick writes a label
            new = {}
            for k, v in lb.items():
                new[k] = v
                if k == "vulnerability":
                    new["aliases"] = [alias]
            lb.clear()
            lb.update(new)
        if n["scan"] + n["db"]:
            docs[p]["schema"] = vml_convert.SCHEMA_VERSION
            p.write_text(vml_convert.marshal(docs[p]))
            print(f"{p.relative_to(CORPUS)}: {n['scan']} from the scan, {n['db']} from the DB")
    for line in none:
        print(f"no CVE to alias: {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
