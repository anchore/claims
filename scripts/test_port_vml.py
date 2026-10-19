import json
import tempfile
import unittest
from pathlib import Path

import port_vml

D = "sha256:" + "a" * 64


class TestPortVML(unittest.TestCase):
    def test_split_ref(self):
        cases = {
            f"anchore/test_images@{D}": "docker.io/anchore/test_images",
            f"docker.io/postgres:13.2@{D}": "docker.io/library/postgres",
            f"alpine@{D}": "docker.io/library/alpine",
            f"ghcr.io/anchore/test-images/java:56d52bc@{D}": "ghcr.io/anchore/test-images/java",
            f"localhost:5000/x/y:tag@{D}": "localhost:5000/x/y",
        }
        for exact, repo in cases.items():
            self.assertEqual(port_vml.split_ref(exact), (repo, D), exact)

    def test_ghcr_ref(self):
        self.assertEqual(
            port_vml.ghcr_ref("vulnerabilities-alpine-3.11-d5be50d", D), f"ghcr.io/anchore/test-images/vulnerabilities-alpine-3.11:d5be50d@{D}"
        )
        self.assertIsNone(port_vml.ghcr_ref("vulnerabilities-package-name-normalization", D))
        self.assertIsNone(port_vml.ghcr_ref("nvidia-pytorch-25.01-py3", D))

    def test_read_vml_concatenated_objects(self):
        with tempfile.TemporaryDirectory() as root:
            d = Path(root) / "labels" / f"anchore+test_images@{D}"
            d.mkdir(parents=True)
            a, b = {"ID": "a", "image": {"exact": "x"}}, {"ID": "b", "image": {"exact": "x"}}
            (d / "f.json").write_text(json.dumps(a) + "\n" + json.dumps(b) + "\n\n")
            got = port_vml.read_vml(Path(root))
            self.assertEqual(got, {d.name: [("f.json", [a, b])]})


if __name__ == "__main__":
    unittest.main()
