# claims

Labeled vulnerability matches: for a package in a known image, is a given vulnerability really there? Each label says `tp` (the installed code is vulnerable), `fp` (it isn't) or `unclear` (nobody has shown either), with a justification and the evidence behind it.

This is the ground truth [yardstick](https://github.com/anchore/yardstick) scores grype against. A yardstick gate scans a set of images with two grype setups and uses these labels to tell whether a change made matching better or worse.

It replaces [vulnerability-match-labels](https://github.com/anchore/vulnerability-match-labels), whose labels were ported here.

What it is not:

- not a vulnerability database or feed: a label is about one package version in one image, not about a CVE in general
- not a risk or severity rating: a label states whether the code is vulnerable, never whether anyone should care (see P-1 in the labeling policy)
- not where SBOMs are stored: they live in R2 (see below)

## How it's used

yardstick reads the published snapshot by default (`github.com/anchore/claims@main` as a claims source), so nobody needs a checkout just to run a gate. To add labels:

1. run a gate and label what changed with `yardstick claims serve` (or `yardstick claims add`), which writes to a local scratch directory
2. `yardstick claims promote <scratch dir> --to <this checkout>` to move the labels here
3. `make validate-changed`, then open a pull request

The walkthrough in yardstick's [demo](https://github.com/anchore/yardstick/tree/go-rewrite/demo) does all of it with real output.

## What's here

- `pkg/oci/<registry>/<repository>/sha256-<digest>/` is one image: its labels sit in a directory per kind of label, and today the only kind is `matches/`, with `<type>.json` per package type (`apk.json`, `rpm.json`, `go-module.json`, ...) and `image.json` for labels that name no package. The image's SBOM, when fetched, sits beside `matches/` as `sbom.syft.json`
- `sbom/sha256-<digest>/matches/` is the same for a subject that is an SBOM rather than an image, and `global/matches/<type>.json` holds labels that apply to every subject. Neither has any labels yet
- `catalog.yaml` pins the syft version and platform every image's SBOM is built with
- `vocabulary.yaml` lists the allowed justifications, fact sources and namespaces, and the labeling rules: each rule's verdict, confidence ceiling and the policy decision behind it
- `labeling-policy.md` says what a label means, what each kind of evidence can support, and the decisions (P-1, P-2, ...) the rules cite. Change a rule in `vocabulary.yaml` and its decision here in the same pull request
- `publish.yaml` names the label file format this corpus is in (`v1`) and which snapshot `latest` points at
- `schema/` holds the JSON schema label files are validated against (`yardstick claims schema` writes it)
- `scripts/` holds the bundling, publishing, SBOM and validation scripts, plus the one-time port from vulnerability-match-labels
- `Taskfile.yaml`, `Makefile` and `.binny.yaml` hold the tasks and pinned tools, including the yardstick that validates the corpus. `make help` lists the tasks

## Publishing

Every merge to `main` that touches the corpus is validated, bundled and published to the `oss-prod-yardstick` R2 bucket, served at `https://yardstick.anchore.io`:

- `claims/matches/snapshots/<sha256>.zip` is the corpus at that commit, named by its digest and never overwritten
- `claims/matches/commits/<sha>.json` names the snapshot for a commit
- `claims/matches/latest-v1.json` names the snapshot yardstick's `@main` reads. It follows the tip of `main` unless `publish.yaml` pins it to a commit
- `claims/schema/schema-<version>.json` is the label file schema
- `claims/pkg/oci/.../sbom.syft-v<version>.json` is each image's SBOM, built by the syft in `catalog.yaml` and uploaded once

A snapshot holds only the corpus (`catalog.yaml`, `vocabulary.yaml`, `pkg/`, `sbom/`, `global/`). `make sboms` fetches the SBOMs into a checkout, building any R2 doesn't have yet.
