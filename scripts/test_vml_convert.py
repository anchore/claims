import gzip
import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

import port_vml
import sboms
import vml_convert as vc

TESTDATA = Path(__file__).parent / "testdata"
ALPINE = "docker.io/alpine@sha256:ddac200f3ebc9902fb8cfcd599f41feb2151f1118929da21bcef57dc276975f9"
JAVA = "docker.io/anchore/test_images@sha256:b3534fc2e37943136d5b54e3a58b55d4ccd4363d926cf7aa5bf55a524cf8275b"
AMAZONLINUX_2 = "docker.io/amazonlinux@sha256:1301cc9f889f21dc45733df9e58034ac1c318202b4b0f0a08d88b3fdc03004de"
VOCAB = vc.Vocabulary(advisory_ids=["ALAS*", "ELSA"], namespaces=["CVE", "GHSA"])


def sbom_for(repository, digest):
    """The fixture SBOMs: vulnerability-match-labels' published ones, as the corpus would hold them."""
    name = f"{repository.replace('/library/', '/').replace('/', '+')}@{digest.replace(':', '-')}.syft.json.gz"
    path = TESTDATA / name
    if not path.exists():
        return None
    with tempfile.NamedTemporaryFile("wb", suffix=".json") as f:
        f.write(gzip.decompress(path.read_bytes()))
        f.flush()
        return vc.SbomIndex.read(f.name, digest)


def label(vid, verdict="TP", pkg=("libcrypto1.0", "1.0.2k-r0"), image=ALPINE, **extra):
    out = {"ID": f"id-{vid}-{extra.get('user', 'alice')}", "image": {"exact": image}, "label": verdict, "timestamp": "2024-11-01T00:00:00+00:00"}
    out.update({"user": "alice", "vulnerability_id": vid, **extra})
    if pkg:
        out["package"] = {"name": pkg[0], "version": pkg[1]}
    return out


def convert(records, lookup=None):
    return vc.convert(records, VOCAB, port_vml.split_ref, sbom_for, lookup or (lambda ids: {}))


def labels_in(files, rel):
    return {(lb["package"], lb["vulnerability"]): lb for lb in files[rel]["labels"]}


class TestHelpers(unittest.TestCase):
    def test_parse_tool(self):
        cases = {
            "grype@v0.74.2": ("grype", "v0.74.2"),
            "grype@v0.51.0-7-gfcce63b": ("grype", "v0.51.0-7-gfcce63b"),
            "grype[custom-db]@v0.77.4": ("grype", "v0.77.4"),
            "grype@v0.63.1+profile=cpe": ("grype", "v0.63.1"),
            "anchorectl@v5.20.0-rc1+enterprise=5.20.0": ("anchorectl", "v5.20.0-rc1"),
            None: ("", ""),
        }
        for tool, want in cases.items():
            self.assertEqual(vc.parse_tool(tool), want, tool)

    def test_syft_at(self):
        at = lambda s: datetime.fromisoformat(s)
        self.assertIsNone(vc.syft_at(at("2022-09-15T00:00:00+00:00")))
        self.assertEqual(vc.syft_at(at("2022-10-01T00:00:00+00:00")), "v0.54.0")
        self.assertIsNone(vc.syft_at(at("2023-03-11T00:00:00+00:00")))  # pinned to latest
        self.assertEqual(vc.syft_at(at("2026-01-01T00:00:00+00:00")), "v1.14.0")
        # anchorectl never scanned a pinned syft's SBOM
        self.assertEqual(
            vc.seen_tools("anchorectl@v1.3.0+enterprise=4.4.0", at("2026-01-01T00:00:00+00:00")), [{"name": "anchorectl", "version": "v1.3.0"}]
        )

    def test_vml_sbom_ref(self):
        hex_ = "sha256-ddac200f3ebc9902fb8cfcd599f41feb2151f1118929da21bcef57dc276975f9"
        cases = {
            ALPINE: f"ghcr.io/anchore/vml-sbom/docker.io/alpine:{hex_}",
            ALPINE.replace("docker.io/", ""): f"ghcr.io/anchore/vml-sbom/docker.io/alpine:{hex_}",
            ALPINE.replace("@", ":3.6@"): f"ghcr.io/anchore/vml-sbom/docker.io/alpine:{hex_}",
            "anchore/test_images@sha256:ab": "ghcr.io/anchore/vml-sbom/docker.io/anchore/test_images:sha256-ab",
            "mcr.microsoft.com/cbl-mariner/base/core@sha256:ab": "ghcr.io/anchore/vml-sbom/mcr.microsoft.com/cbl-mariner/base/core:sha256-ab",
        }
        for exact, want in cases.items():
            self.assertEqual(port_vml.vml_sbom_ref(exact), want, exact)

    def test_sbom_paths(self):
        d = "pkg/oci/ghcr.io/anchore/test-images/bitnami/spark/sha256-267d"
        self.assertEqual(sboms.image_ref(d), "ghcr.io/anchore/test-images/bitnami/spark@sha256:267d")
        self.assertEqual(sboms.r2_key(d, "1.14.0"), f"claims/{d}/sbom.syft-v1.14.0.json")

    def test_parse_time(self):
        self.assertEqual(vc.rfc3339(vc.parse_time("2022-09-15T14:54:05-04:00")), "2022-09-15T18:54:05Z")
        self.assertEqual(vc.rfc3339(vc.parse_time("2023-05-10T11:38:00.253514")), "2023-05-10T11:38:00Z")
        self.assertEqual(vc.rfc3339(vc.parse_time("2022-05-01 10:00:00")), "2022-05-01T10:00:00Z")
        self.assertEqual(vc.parse_time("2022-06-01"), datetime(2022, 6, 1, tzinfo=UTC))

    def test_label_purl(self):
        self.assertEqual(vc.label_purl("pkg:rpm/ol/dhclient@4.1.1?arch=x86_64&epoch=12&upstream=dhcp"), "pkg:rpm/ol/dhclient@4.1.1?epoch=12")
        self.assertEqual(vc.label_purl("pkg:apk/alpine/musl@1.1.16-r14?arch=x86_64&distro=alpine-3.6"), "pkg:apk/alpine/musl@1.1.16-r14")

    def test_vocabulary(self):
        v = vc.Vocabulary.read(Path(__file__).parent.parent / "vocabulary.yaml")
        self.assertTrue(v.is_advisory("ALAS2-2021-1") and v.is_advisory("ELSA-2022-9246"))
        self.assertTrue(v.accepts("CVE-2021-1") and v.accepts("GHSA-x") and v.accepts("ELSA-2022-1") and not v.accepts("FOO-1"))


class TestConvert(unittest.TestCase):
    def test_real_alpine_labels(self):
        # every label vulnerability-match-labels holds for this image, as it holds them
        d = TESTDATA / "vml" / "labels" / "docker.io+alpine@sha256-ddac200f3ebc9902fb8cfcd599f41feb2151f1118929da21bcef57dc276975f9"
        records = [(f.name, json.loads(f.read_text())) for f in sorted(d.glob("*.json"))]
        files, entries = convert(records)
        self.assertEqual({e["outcome"] for e in entries}, {vc.MIGRATED}, [e for e in entries if e["outcome"] != vc.MIGRATED])
        rel = "pkg/oci/docker.io/library/alpine/sha256-ddac200f3ebc9902fb8cfcd599f41feb2151f1118929da21bcef57dc276975f9/matches/apk.json"
        self.assertEqual(list(files), [rel])
        # the digest is an index, so the file says which platform's packages the SBOM cataloged
        self.assertEqual(
            files[rel]["subject"],
            {"image": "docker.io/library/alpine@sha256:ddac200f3ebc9902fb8cfcd599f41feb2151f1118929da21bcef57dc276975f9", "platform": "linux/amd64"},
        )
        got = labels_in(files, rel)
        self.assertEqual(len(got), 62)

        # no tool, and made before any syft was pinned: nothing to say it was seen in
        lb = got[("pkg:apk/alpine/libcrypto1.0@1.0.2k-r0", "CVE-2018-5407")]
        self.assertEqual(lb["verdict"], "tp")
        self.assertNotIn("seenIn", lb)
        self.assertEqual(
            lb["notes"],
            [
                {
                    "text": "ported from vulnerability-match-labels 142c3a49-66a7-40d0-beba-9e104d3db7e1: tp. upto (excluding) 1.0.2q",
                    "author": "wagoodman",
                    "at": "2022-09-15T18:54:05Z",
                }
            ],
        )
        # grype, named whole in the note, and the syft pinned that day in seenIn
        seen = [lb for lb in got.values() if "v0.59.0" in lb["notes"][0]["text"]]
        self.assertTrue(seen)
        self.assertEqual(seen[0]["seenIn"], {"tools": [{"name": "grype", "version": "v0.59.0-1-gde25eb9"}, {"name": "syft", "version": "v0.74.0"}]})
        self.assertTrue(seen[0]["notes"][0]["text"].endswith(" with grype@v0.59.0-1-gde25eb9"))

    def test_real_amazonlinux_2_labels(self):
        # vulnerability-match-labels names Amazon Linux 2 advisories ALAS-..., which grype's DB holds as ALAS2-...
        d = TESTDATA / "vml" / "labels" / f"docker.io+amazonlinux@{AMAZONLINUX_2.split('@')[1].replace(':', '-')}"
        records = [(f.name, json.loads(f.read_text())) for f in sorted(d.glob("*.json"))]
        db = vc.parse_grype_search(gzip.decompress((TESTDATA / "grype-db-search-amazonlinux-2.json.gz").read_bytes()))
        asked = []
        files, entries = convert(records, lambda ids: asked.extend(ids) or {i: db[i] for i in ids if i in db})
        self.assertTrue(asked and all(i.startswith("ALAS2-") for i in asked), asked)
        self.assertEqual({e["outcome"] for e in entries}, {vc.MIGRATED}, [e for e in entries if e["outcome"] != vc.MIGRATED])
        (rel,) = files
        self.assertTrue(rel.endswith("/amazonlinux/sha256-1301cc9f889f21dc45733df9e58034ac1c318202b4b0f0a08d88b3fdc03004de/matches/rpm.json"))
        got = labels_in(files, rel)
        # every call stays on its advisory, under the id grype's DB uses, with its verdict
        for (_, src), e in zip(records, entries):
            (b,) = e["became"]
            self.assertEqual(
                (b["vulnerability"], b["verdict"]), (vc.db_advisory(src["vulnerability_id"], "amzn:2"), vc.VERDICTS[src["label"]]), e["id"]
            )
        self.assertTrue(all(v.startswith("ALAS2-") for _, v in got))
        lb = got[("pkg:rpm/amzn/elfutils-libelf@0.176-2.amzn2", "ALAS2-2023-2197")]
        self.assertEqual(lb["verdict"], "tp")
        self.assertIn("tp on ALAS-2023-2197, which grype's DB now names ALAS2-2023-2197", lb["notes"][0]["text"])
        # one naming several CVEs keeps its verdict too, rather than becoming unclear on each CVE
        multi = [k for k in got if len(db[k[1]]) > 1]
        self.assertTrue(multi)
        self.assertEqual({got[k]["verdict"] for k in multi} - {"tp", "fp"}, set())

    def test_alas_renamed_only_on_amazonlinux_2(self):
        self.assertEqual(vc.db_advisory("ALASKERNEL-5.10-2022-005", "amzn:2"), "ALAS2KERNEL-5.10-2022-005")
        self.assertEqual(vc.db_advisory("ALAS2-2023-2197", "amzn:2"), "ALAS2-2023-2197")
        self.assertEqual(vc.db_advisory("ALAS-2023-2197", "amzn:2018.03"), "ALAS-2023-2197")
        self.assertEqual(vc.db_advisory("ELSA-2022-1", "amzn:2"), "ELSA-2022-1")

    def test_merges_keep_every_call(self):
        files, _ = convert(
            [
                ("a", label("CVE-2018-5407", "TP", user="alice", timestamp="2023-01-01T00:00:00+00:00", tool="grype@v0.56.0")),
                ("b", label("CVE-2018-5407", "FP", user="bob", timestamp="2024-11-01T00:00:00+00:00", tool="grype@v0.83.0", note="NOT_REACHABLE")),
            ]
        )
        (f,) = files.values()
        (lb,) = f["labels"]
        self.assertEqual((lb["verdict"], lb["justification"], lb["author"]), ("unclear", vc.LABELERS_DISAGREE, "alice, bob"))
        self.assertEqual((lb["firstIssued"], lb["lastUpdated"]), ("2023-01-01T00:00:00Z", "2024-11-01T00:00:00Z"))
        self.assertEqual([n["author"] for n in lb["notes"]], ["alice", "bob"])
        self.assertEqual(lb["notes"][1]["text"], "ported from vulnerability-match-labels id-CVE-2018-5407-bob: fp with grype@v0.83.0. NOT_REACHABLE")
        # the latest call's tools
        self.assertEqual(lb["seenIn"]["tools"], [{"name": "grype", "version": "v0.83.0"}, {"name": "syft", "version": "v1.14.0"}])

    def test_location(self):
        # a nested archive's virtual path names one package; the outer jar holds 65, so it names none
        nested = "/usr/local/packages/maven/target/my-app-1.jar:org.codehaus.mojo:animal-sniffer-annotations"
        files, entries = convert(
            [
                ("a", label("CVE-2020-1234", "FP", pkg=None, image=JAVA, fullentry_fields=[nested])),
                ("b", label("CVE-2020-1234", "FP", pkg=None, image=JAVA, fullentry_fields=["/usr/local/packages/maven/target/my-app-1.jar"])),
            ]
        )
        self.assertEqual([e["outcome"] for e in entries], [vc.MIGRATED, vc.NO_PACKAGE])
        (rel,) = files
        self.assertTrue(rel.endswith("/matches/java-archive.json"))
        (lb,) = files[rel]["labels"]
        self.assertEqual(lb["package"], "pkg:maven/org.codehaus.mojo/animal-sniffer-annotations@1.14")
        self.assertIn(f"on the package at {nested}", lb["notes"][0]["text"])

    def test_unconverted(self):
        _, entries = convert(
            [
                ("a", label("CVE-1", pkg=("not-a-package", "1.0"))),
                ("b", label("CVE-1", image="docker.io/library/debian@sha256:" + "0" * 64)),
                ("c", label("CVE-1", pkg=None)),
                ("d", label("CVE-1", verdict="maybe")),
                ("e", label("FOO-2021-5")),
            ]
        )
        self.assertEqual([e["outcome"] for e in entries], [vc.NOT_IN_SBOM, vc.NO_SBOM, vc.NO_PACKAGE, vc.UNREADABLE, vc.REFUSED])


ORACLE_6 = "pkg/oci/docker.io/library/oraclelinux/sha256-a06327c0f1d18d753f2a60bb17864c84a850bb6dcbcf5946dd1a8123f6e75495"
ORACLE_8 = "pkg/oci/ghcr.io/anchore/test-images/appstreams-oraclelinux-8/sha256-c8d664b0e728d52f57eeb98ed1899c16d3b265f02ddfb41303d7a16c31e0b0f1"
AMAZONLINUX_2_TEST = (
    "pkg/oci/ghcr.io/anchore/test-images/vulnerabilities-amazonlinux-2/sha256-cf742eca189b02902a0a7926ac3fbb423e799937bf4358b0d2acc6cc36ab82aa"
)


class TestAdvisoryLabels(unittest.TestCase):
    """The port of advisory calls, and the cleanup of the labels an earlier port moved from advisories to CVEs."""

    db = vc.parse_grype_search(gzip.decompress((TESTDATA / "grype-db-search-advisories.json.gz").read_bytes()))

    def port(self, image_dir):
        """Convert the fixture labels of one corpus image, as port does: test_images are named by their ghcr mirror."""
        repo, digest = image_dir.removeprefix("pkg/oci/").rsplit("/", 1)
        digest = digest.replace("-", ":", 1)
        vml = repo.replace("docker.io/library/", "docker.io/")
        if repo.startswith("ghcr.io/anchore/test-images/"):
            vml = "docker.io/anchore/test_images"
        records = []
        for f in sorted((TESTDATA / "vml" / "labels" / f"{vml.replace('/', '+')}@{digest.replace(':', '-')}").glob("*.json")):
            src = json.loads(f.read_text())
            src["image"]["exact"] = f"{repo}@{digest}"
            records.append((f.name, src))
        files, entries = convert(records, lambda ids: {i: self.db[i] for i in ids if i in self.db})
        return records, files, entries

    def committed(self, rel):
        return json.loads((TESTDATA / "corpus" / rel).read_text())["labels"]

    def test_advisories_stay_on_the_advisory(self):
        records, files, entries = self.port(ORACLE_6)
        self.assertEqual({e["outcome"] for e in entries}, {vc.MIGRATED})
        got = labels_in(files, f"{ORACLE_6}/matches/rpm.json")
        elsa = [(src, e) for (_, src), e in zip(records, entries) if src["vulnerability_id"].startswith("ELSA-")]
        self.assertEqual(len(elsa), 13)
        for src, e in elsa:
            (b,) = e["became"]
            self.assertEqual((b["vulnerability"], b["verdict"]), (src["vulnerability_id"], "tp"), e["id"])
        # no CVE label comes from an advisory, whether it names one CVE or several
        self.assertEqual({v for _, v in got}, {src["vulnerability_id"] for src, _ in elsa})
        self.assertEqual(self.db["ELSA-2021-9137"], ["CVE-2020-1971"])
        self.assertEqual(got[("pkg:rpm/ol/openssl@1.0.1e-58.0.1.el6_10", "ELSA-2021-9137")]["verdict"], "tp")
        self.assertEqual(len(self.db["ELSA-2022-9359"]), 3)
        lb = got[("pkg:rpm/ol/expat@2.0.1-13.el6_8", "ELSA-2022-9359")]
        self.assertEqual(lb["verdict"], "tp")
        self.assertNotIn("CVE", lb["notes"][0]["text"])

    def test_cve_and_ghsa_labels_unchanged(self):
        # the python labels came from CVE and GHSA calls, so the port writes them as the earlier one did
        _, files, _ = self.port(ORACLE_6)
        rel = f"{ORACLE_6}/matches/python.json"
        self.assertEqual(files[rel]["labels"], self.committed(rel))
        self.assertEqual({lb["vulnerability"].split("-")[0] for lb in files[rel]["labels"]}, {"CVE", "GHSA"})

    def test_unresolvable_advisory_reported(self):
        _, files, entries = self.port(AMAZONLINUX_2_TEST)
        by_vuln = {e["vulnerability"]: e for e in entries}
        for vid, named in (("ALAS-2022-1814", "ALAS2-2022-1814"), ("ALASKERNEL-5.4-2022-027", "ALAS2KERNEL-5.4-2022-027")):
            self.assertEqual((by_vuln[vid]["outcome"], by_vuln[vid]["named"]), (vc.NOT_IN_DB, named))
            self.assertNotIn("became", by_vuln[vid])
        got = labels_in(files, f"{AMAZONLINUX_2_TEST}/matches/rpm.json")
        self.assertEqual(list(got), [("pkg:rpm/amzn/kernel-headers@4.14.275-207.503.amzn2", "ALAS2KERNEL-5.4-2022-015")])
        self.assertEqual(by_vuln["GHSA-pjjw-qhg8-p2p9"]["became"][0]["vulnerability"], "GHSA-pjjw-qhg8-p2p9")

    def test_cleanup_removes_derived_labels_only(self):
        _, files, _ = self.port(ORACLE_6)
        rel = f"{ORACLE_6}/matches/rpm.json"
        old = self.committed(rel)
        # somebody added a note to one moved label since the port, so its origin is no longer only the port
        touched = {**old[0], "notes": [*old[0]["notes"], {"text": "checked the changelog", "author": "someone", "at": "2026-10-20T00:00:00Z"}]}
        labels, ch = vc.reconcile([touched, *old[1:]], files[rel]["labels"])
        self.assertTrue(all(vc.dereferenced(lb) for lb in old))
        self.assertEqual(ch["removed"], old[1:])
        self.assertEqual(ch["kept"], [touched])
        self.assertEqual(len(ch["added"]), 13)
        self.assertIn(touched, labels)
        self.assertEqual({lb["vulnerability"] for lb in labels if lb is not touched}, {lb["vulnerability"] for lb in files[rel]["labels"]})
        # a file with no moved labels comes through untouched
        py = f"{ORACLE_6}/matches/python.json"
        labels, ch = vc.reconcile(self.committed(py), files[py]["labels"])
        self.assertEqual((labels, ch), (self.committed(py), {"removed": [], "added": [], "kept": [], "differs": []}))

    def test_cleanup_splits_a_label_merged_with_an_advisory(self):
        # the earlier port merged a call on ELSA-2022-1860 (naming only CVE-2020-13956) into the CVE label from a CVE call
        _, files, _ = self.port(ORACLE_8)
        rel = f"{ORACLE_8}/matches/rpm.json"
        old = [lb for lb in self.committed(rel) if "/aopalliance@" in lb["package"]]
        merged = {lb["vulnerability"]: lb for lb in old}["CVE-2020-13956"]
        self.assertEqual(len(merged["notes"]), 2)
        labels, ch = vc.reconcile(old, files[rel]["labels"])
        self.assertEqual((ch["removed"], ch["kept"], ch["differs"]), ([merged], [], []))
        got = {lb["vulnerability"]: lb for lb in labels}
        self.assertEqual(sorted(got), ["CVE-2020-13956", "CVE-2022-29599", "ELSA-2022-1860"])
        self.assertEqual([n["text"].split()[3] for n in got["CVE-2020-13956"]["notes"]], ["f26393c6-86cd-447e-8b9f-876561a305a7:"])
        self.assertEqual(got["CVE-2022-29599"], {lb["vulnerability"]: lb for lb in old}["CVE-2022-29599"])
        self.assertEqual(got["ELSA-2022-1860"]["verdict"], "tp")


if __name__ == "__main__":
    unittest.main()
