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
        self.assertTrue(v.accepts("CVE-2021-1") and v.accepts("GHSA-x") and not v.accepts("ELSA-2022-1") and not v.accepts("FOO-1"))


class TestConvert(unittest.TestCase):
    def test_real_alpine_labels(self):
        # every label vulnerability-match-labels holds for this image, as it holds them
        d = TESTDATA / "vml" / "labels" / "docker.io+alpine@sha256-ddac200f3ebc9902fb8cfcd599f41feb2151f1118929da21bcef57dc276975f9"
        records = [(f.name, json.loads(f.read_text())) for f in sorted(d.glob("*.json"))]
        files, entries = convert(records)
        self.assertEqual({e["outcome"] for e in entries}, {vc.MIGRATED}, [e for e in entries if e["outcome"] != vc.MIGRATED])
        rel = "pkg/oci/docker.io/library/alpine/sha256-ddac200f3ebc9902fb8cfcd599f41feb2151f1118929da21bcef57dc276975f9/apk.json"
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

    def test_advisories(self):
        lookup = {"ALAS-2021-1": ["CVE-2021-1"], "ALAS-2021-2": ["CVE-2021-2", "CVE-2021-3", "ELSA-2021-9"], "ALAS-2021-4": []}
        files, entries = convert(
            [
                ("a", label("ALAS-2021-1", "FP")),
                ("b", label("ALAS-2021-2", "TP")),
                ("c", label("ALAS-2021-4", "TP")),
                ("d", label("FOO-2021-5", "TP")),
            ],
            lambda ids: {i: lookup[i] for i in ids},
        )
        self.assertEqual([e["outcome"] for e in entries], [vc.CARRIED, vc.FANNED_OUT, vc.NO_CVE, vc.REFUSED])
        (f,) = files.values()
        got = {lb["vulnerability"]: lb for lb in f["labels"]}
        # one CVE: the verdict moves to it; several: unclear on each, and only the accepted ids
        self.assertEqual((got["CVE-2021-1"]["verdict"], got["CVE-2021-1"]["justification"]), ("fp", vc.NOT_RECORDED))
        self.assertIn("on ALAS-2021-1, which names only CVE-2021-1", got["CVE-2021-1"]["notes"][0]["text"])
        self.assertEqual(sorted(got), ["CVE-2021-1", "CVE-2021-2", "CVE-2021-3"])
        self.assertEqual((got["CVE-2021-2"]["verdict"], got["CVE-2021-2"]["justification"]), ("unclear", vc.NOT_ASSESSED))

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
        self.assertTrue(rel.endswith("/java-archive.json"))
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
            ]
        )
        self.assertEqual([e["outcome"] for e in entries], [vc.NOT_IN_SBOM, vc.NO_SBOM, vc.NO_PACKAGE, vc.UNREADABLE])


if __name__ == "__main__":
    unittest.main()
