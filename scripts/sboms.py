#!/usr/bin/env python3
"""Fetch, build and upload the SBOM of every image in the corpus.

SBOMs are not committed. An image's directory and catalog.yaml are the recipe for its SBOM, and
the SBOM itself lives in R2 at the same path under claims/, named by the syft that built it:

  pkg/oci/<registry>/<repository>/sha256-<hex>/sbom.syft.json                       (local, ignored)
  claims/pkg/oci/<registry>/<repository>/sha256-<hex>/sbom.syft-v<version>.json     (R2, write-once)

  sboms.py fetch [-v] [<image dir>...]
                     download each labeled image's SBOM for catalog.yaml's syft, building any R2 lacks;
                     -v prints what happened to each image rather than only the totals
  sboms.py upload [-v]
                     put every local SBOM R2 lacks (needs R2_BUCKET and the aws cli's credentials);
                     DRY_RUN=1 makes no put; -v prints what happened to each SBOM rather than only the totals

Fetching reads R2 over public HTTPS, so it needs no credential.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

CORPUS = Path(__file__).resolve().parent.parent
SBOM = "sbom.syft.json"
# the same variable yardstick reads published snapshots from
URL_VAR = "YARDSTICK_CLAIMS_URL"
# the public custom domain of the bucket publish.yaml writes to
DEFAULT_URL = "https://yardstick.anchore.io"


class Abort(Exception):
    pass


def catalog_syft():
    """Return the syft version catalog.yaml pins, without its 'v', or None when it pins none."""
    text = (CORPUS / "catalog.yaml").read_text()
    # ponytail: a config changes what syft writes, so it would need its hash in the R2 name; none is set yet
    if re.search(r"^config:", text, re.MULTILINE):
        raise Abort("catalog.yaml sets a syft config, and R2 names SBOMs by syft version alone; add the config's hash to the name first")
    m = re.search(r"^syft:\s*syft@v?(\S+)", text, re.MULTILINE)
    return m.group(1) if m else None


def base_url():
    return (os.environ.get(URL_VAR) or DEFAULT_URL).rstrip("/")


def r2_key(d, version):
    return f"claims/{d}/sbom.syft-v{version}.json"


def image_ref(d):
    """Return the image an image directory names: pkg/oci/<registry>/<repository>/sha256-<hex>."""
    parts = d.split("/")
    return f"{'/'.join(parts[2:-1])}@{parts[-1].replace('-', ':', 1)}"


def local_version(d):
    f = CORPUS / d / SBOM
    return json.loads(f.read_text())["descriptor"]["version"] if f.exists() else None


def labeled_dirs():
    """Return every image directory holding a label file."""
    return sorted({f.parent.relative_to(CORPUS).as_posix() for f in (CORPUS / "pkg" / "oci").rglob("*.json") if f.name != SBOM})


def download(d, version):
    """Return the SBOM R2 holds for an image and syft version, or None when it holds none."""
    url = f"{base_url()}/{r2_key(d, version)}"
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / SBOM
        # curl rather than urllib: python.org builds on macOS ship without a CA bundle
        res = subprocess.run(
            ["curl", "-sS", "--max-time", "600", "-o", str(out), "-w", "%{http_code}", url], capture_output=True, text=True, check=False
        )
        if res.stdout in ("404", "403"):
            return None
        if res.returncode != 0 or res.stdout != "200":
            raise Abort(f"downloading {url} failed ({res.stdout}): {res.stderr.strip()}")
        data = out.read_bytes()
    if json.loads(data)["descriptor"]["version"] != version:
        raise Abort(f"{url} was not built with syft {version}")
    return data


def ensure(d, yardstick, fallback=None):
    """Make sure an image directory holds its SBOM for catalog.yaml's syft, and say how.

    In order: the one already there, R2's, fallback() (bytes or None, for a source of SBOMs that
    predates R2), then a build with `yardstick collect sboms`. Returns have, downloaded, seeded,
    built or failed.
    """
    version = catalog_syft()
    if local_version(d) == version:
        return "have"
    data = download(d, version)
    how = "downloaded"
    if data is None and fallback and (data := fallback()):
        how = "seeded"
    if data is not None:
        (CORPUS / d).mkdir(parents=True, exist_ok=True)
        (CORPUS / d / SBOM).write_bytes(data)
        return how
    print(f"building the SBOM for {image_ref(d)}", flush=True)
    res = subprocess.run([yardstick, "collect", "sboms", f"oci:{image_ref(d)}"], cwd=CORPUS, check=False)
    if res.returncode != 0:
        return "failed"
    if (got := local_version(d)) != version:
        raise Abort(f"{d}: built with syft {got}, where catalog.yaml pins {version}")
    return "built"


def cmd_fetch(args):
    counts, failed = {}, []
    for d in args.dirs or labeled_dirs():
        how = ensure(d.rstrip("/"), args.yardstick)
        if args.verbose:
            print(f"{how:<10} {image_ref(d.rstrip('/'))}", flush=True)
        counts[how] = counts.get(how, 0) + 1
        if how == "failed":
            failed.append(d)
    print(f"SBOMs for syft {catalog_syft()}: " + ", ".join(f"{n} {how}" for how, n in sorted(counts.items())))
    for d in failed:
        print(f"  could not build {d}", file=sys.stderr)
    return 1 if failed else 0


def s3(*args):
    return subprocess.run(["aws", "s3api", *args, "--bucket", os.environ["R2_BUCKET"]], capture_output=True, text=True, check=False)


def cmd_upload(args):
    if not os.environ.get("R2_BUCKET"):
        raise Abort("R2_BUCKET is not set")
    put, have, seen = 0, 0, None
    for f in sorted((CORPUS / "pkg" / "oci").rglob(SBOM)):
        d = f.parent.relative_to(CORPUS).as_posix()
        # named by the syft the SBOM says built it, not by what catalog.yaml pins
        key = r2_key(d, local_version(d))
        # check first, so an SBOM R2 already holds is not sent again
        res = s3("head-object", "--key", key)
        if res.returncode == 0:
            have += 1
            seen = seen or key
            if args.verbose:
                print(f"{'have':<10} {key}", flush=True)
            continue
        if "Not Found" not in res.stderr and "404" not in res.stderr:
            raise Abort(f"checking {key} failed: {res.stderr.strip()}")
        if os.environ.get("DRY_RUN") == "1":
            put += 1
            if args.verbose:
                print(f"{'would put':<10} {key}", flush=True)
            continue
        res = s3(
            "put-object",
            "--key",
            key,
            "--body",
            str(f),
            "--content-type",
            "application/json",
            "--cache-control",
            "public, max-age=31536000, immutable",
            "--if-none-match",
            "*",
        )
        if res.returncode != 0 and "PreconditionFailed" not in res.stderr:
            raise Abort(f"putting {key} failed: {res.stderr.strip()}")
        if args.verbose:
            print(f"{'put':<10} {key}", flush=True)
        put += 1
        seen = seen or key
    print(f"{'would upload' if os.environ.get('DRY_RUN') == '1' else 'uploaded'} {put} SBOMs, {have} already in R2")
    # fetch reads over public HTTPS: a host that does not serve this bucket would make every fetch
    # miss and rebuild, with nothing failing
    if seen and os.environ.get("DRY_RUN") != "1":
        url = f"{base_url()}/{seen}"
        res = subprocess.run(["curl", "-sS", "-o", os.devnull, "-I", "-w", "%{http_code}", url], capture_output=True, text=True, check=False)
        if res.stdout != "200":
            raise Abort(f"R2 holds {seen}, but {url} answers {res.stdout or res.stderr.strip()}; set {URL_VAR} to the bucket's public host")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    fetch = sub.add_parser("fetch", help="download or build every labeled image's SBOM")
    fetch.add_argument(
        "--yardstick", default=str(CORPUS / ".tool" / "yardstick"), help="the yardstick binary (default: the one .binny.yaml pins, from `make tools`)"
    )
    fetch.add_argument("-v", "--verbose", action="store_true", help="print what happened to each image: have, downloaded, seeded, built or failed")
    fetch.add_argument("dirs", nargs="*", help="only these image directories (default: every one holding labels)")
    fetch.set_defaults(fn=cmd_fetch)
    upload = sub.add_parser("upload", help="put every local SBOM R2 lacks")
    upload.add_argument("-v", "--verbose", action="store_true", help="print what happened to each SBOM: have, put or would put")
    upload.set_defaults(fn=cmd_upload)
    args = parser.parse_args(argv)
    try:
        return args.fn(args)
    except Abort as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
