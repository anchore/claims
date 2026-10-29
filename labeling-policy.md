# Labeling policy

What a label means, which signals can support which verdicts, and the decisions behind that. The
yardstick triage and research skills, the label UI and people labeling by hand follow this.

The rules themselves are data, under `rules:` in [vocabulary.yaml](vocabulary.yaml): every
`evidence[].rule` a label or proposal may cite, with the verdict it supports, the justification its
labels carry, the strongest confidence a proposal citing it may carry, the decision below that allows
it, what it rests on in plain words, and a title for a group of findings sharing it. A label citing an
unlisted rule, or a rule of the other verdict, is refused; a proposal over its rule's ceiling is
flagged. `yardstick claims validate` checks each rule's justification is listed under its verdict.
Change a rule there, and the decision behind it here.

A `*` justification means it depends on the vendor's stated reason, so each label states its own:
"code not present", "code not built" and Red Hat's `vulnerable_code_not_present` or
`component_not_present` give `vulnerable_code_not_present`; "windows only", "only affects ..." give
`other-platform`; "introduced later" gives `introduced-later`; a stated fix gives `fix-installed`;
anything else gives `vendor-not-affected`. A rule with no justification supports either verdict, so
the label states one.

## What a label is

A label states the **truth of a match**: does this package, at this exact version, contain the
vulnerable code without the fix? `tp` means yes, `fp` means no, `unclear` means nobody has shown
either. Severity, exploitability, whether anyone will fix it, and "assume vulnerable until proven
fixed" are consumer policies applied on top of labels; they never change a label.

Confidence says how the author knows. Proposals carry it and labels do not: accepting a proposal drops
its confidence, and a person who accepts one vouches for it.

- **high**: a primary fact states it (a fix version compared with the installed version, the CVE
  rejected by its CNA, the file absent from the binary's file list, code inspection).
- **medium**: inferred (version ranges, a triager's note, a pattern in prior labels).
- **low**: not assessed. A low-confidence `tp` or `fp` is not allowed; use `unclear` and say what
  would settle it in the proposal's `openQuestions`.

## Signals

What a distro tracker status says about the truth of the match, and the strongest verdict it can
support on its own. Combining signals does not raise the ceiling above what the strongest one allows.

| signal | what it says about truth | supports alone |
|---|---|---|
| released, fix version given | the code was affected and this version fixes it; compare with the installed version | tp high / fp high |
| released, no version | affected, fix exists somewhere | tp medium |
| needed, pending | the distro assessed the code as affected | tp high |
| deferred with a reason | assessed as affected, fix postponed | tp high |
| ignored [changes too intrusive], [will not fix] | assessed as affected, never fixing it | tp high |
| not-affected with a reason, DNE | the distro states the code is absent or fixed | fp high |
| not-affected without a reason | a triager's call, no stated basis | fp medium |
| ignored [code not built], [only affects Windows], … | a triager's note about the code, unverified | fp medium |
| ignored (end of standard support), end of life | Canonical marks everything this way at EOL; says nothing | unclear |
| needs-triage, under investigation, deferred without a reason | nobody has looked | unclear |
| not listed | nobody has looked | unclear |
| CVE rejected / withdrawn by its CNA | not a vulnerability | fp high |
| Alpine secdb: CVE under a fixed version for the origin package | Alpine fixed it in that build; compare with the installed apk version | tp high / fp high |
| Alpine secdb: CVE under version "0" | the maintainer states it was never affected, with no reason given | fp medium |
| Alpine secdb: not listed (EOL branches never list newer CVEs) | nobody has looked | unclear; fall back to the CNA range |
| no tracker covers the package (built from source, CPE-matched): CNA range vs installed | an inference | tp medium / fp medium |
| Red Hat VEX: fixed, NEVRA given per stream | the code was affected and this build fixes it; compare with the installed EVR in the package's stream | tp high / fp high |
| Red Hat VEX: known_not_affected with a flag (vulnerable_code_not_present, component_not_present, …) | Red Hat states why the code is absent, per binary RPM | fp high |
| Red Hat VEX: known_not_affected without a flag; Hydra "Not affected" | an assessment with no stated basis | fp medium |
| Red Hat VEX: known_affected; Hydra Affected, Fix deferred, Will not fix | Red Hat assessed the source package as affected | tp high |
| Red Hat: Out of support scope, under investigation, not listed | nobody has looked | unclear |
| vendor statement names a module or library ("only affects mod_proxy") that the binary RPM does not ship | the code is not in this binary, even though its source package is affected | fp high |
| upstream fix version vs installed upstream version | an inference about whether the code is fixed; introduction version unknown | tp medium / fp medium |
| CNA affected range vs installed upstream version | an inference; only meaningful when the CNA product is this package's upstream | tp medium / fp medium |
| the upstream project's GitHub repository advisory range vs installed upstream version | the maintainers' own statement of the affected versions, often the only source that says where the bug was introduced (">= 2.40"); an inference until the code is checked | tp medium / fp medium |
| module, file or program named by the CVE absent from the binary's file list (SBOM), while a sibling package from the same source ships it | the code is not in this binary | fp high |
| GitHub-reviewed advisory names the ecosystem package and its affected range or version list holds the installed version | the maintainers or GitHub's curators assessed this package version as affected | tp high |
| the same, unreviewed advisory | an uncurated report | tp medium |
| ecosystem advisory's fixed version ≤ installed version | the code is fixed in this version | fp high |
| advisory withdrawn | not a vulnerability | fp high |
| CPE match, and the ecosystem advisory for the CVE lists other packages, not this one | a name collision unless this package embeds that code | fp medium |
| CPE match, and no ecosystem advisory exists for the CVE | the CVE is about a product that shares a name with this package | fp medium |
| prior labels on the same package, same kind of bug | a pattern, not a fact | medium |
| EUVD (ENISA) product and version text | the CNA record's text, mirrored; no distro or ecosystem package data | same ceiling as the CNA range (P-4); used only to find a CVE's GHSA id |
| a binary that links a system library which has its own rows | the library's rows carry the verdict | fp medium |

## Decisions

Stable ids; cite them from rules, reviews and the UI. Append, do not renumber.

| id | decision | why | status |
|---|---|---|---|
| P-1 | Claims state the truth of the match, not a business rule. An honest `unclear` stays `unclear`; "assume vulnerable" is applied by consumers, not recorded as `tp`. | Claims feed scores for many consumers with different risk policies. | decided 2026-10-06, Will |
| P-2 | needs-triage, under investigation, deferred without a reason, ignored for end of support, and not-listed are not signals about truth. Alone they support only `unclear`. | Canonical marks every open CVE ignored when a release leaves standard support; needs-triage means nobody looked. | decided 2026-10-06, Will |
| P-3 | A triager's bracketed ignore reason ("code not built", "only affects Windows") or a bare not-affected is an assessment, not verification. Ceiling fp medium. A not-affected with a stated reason is fp high. | The note names a basis a reviewer can check; without one there is nothing to check. | decided 2026-10-06, Will |
| P-4 | A version inference (upstream fix vs installed, CNA range vs installed) supports at most medium, in either direction, and only when the CNA product is the package's upstream. | When the bug was introduced is usually unknown; CNA ranges are often lazy. | decided 2026-10-06, Will |
| P-5 | High confidence needs a primary fact: fix version compared with installed, CVE rejected, file absent from the binary's file list, or code inspection. | Everything else is inference. | decided 2026-10-06, Will |
| P-6 | "needed", "deferred (reason)" and "ignored [changes too intrusive]" are affirmative assessments that the code is affected: tp high. | The distro looked at the code and decided it is affected; they only differ in whether a fix will ship. | decided 2026-10-06, Will |
| P-7 | Proposals are claims by an agent that no person has vouched for. They never count for scoring until a person accepts them. | Keeps the gate honest while hints speed up labeling. | decided 2026-10-06, Will (via the prototype session) |
| P-8 | A GitHub-reviewed advisory that names the ecosystem package, with the installed version in its affected range or version list, is an affirmative assessment like a distro "needed": tp high. Unreviewed advisories cap at medium. Version ordering is the ecosystem's own (PEP 440, Maven, semver), never dpkg. | GitHub reviews advisories with maintainers before marking them reviewed; the package and range are curated per ecosystem. | decided 2026-10-06, Will |
| P-10 | A distro assesses the source package; grype matches every binary built from it. The assessment carries to a binary unless the vendor's per-binary VEX status or the binary's file list shows the vulnerable code is not in it, in which case that binary is fp high (P-5) while its siblings stay tp. | Red Hat and Debian fix at the source level, so "httpd-tools is affected by the mod_proxy DoS" is a side effect of packaging, not a fact about the code. | decided 2026-10-06, Will |
| P-9 | A CPE match that no ecosystem advisory supports is an inference from a name collision: fp medium. It reaches high only after checking the CVE's product against the package (research). A CPE match that the ecosystem advisory does confirm is judged by P-8. Known miss: EOL lines GitHub never mapped (log4j 1.x, CVE-2020-9493) look like collisions; only research catches them. | On the Java and Python test images every labeled CPE true positive has a GHSA naming the package, and the labeled false positives are name collisions (pypi "php", sonarsource "php-checks"). | decided 2026-10-06, Will |
| P-11 | A label on a match grype reported under an advisory id (ALAS2, ELSA, AVG, FEDORA and the rest of vocabulary.yaml's `advisory-ids`) names that advisory, with the verdict on that match. It is never moved to the CVEs the advisory names, whether one or several, and it pairs only a match reporting exactly that id or one of its `aliases`, never an alias group. `aliases` holds the CVE grype's `--by-cve` reports the advisory's match as (the lowest CVE grype's DB names for it; older grype releases reported the first one the DB names, so a label may list both), so the label pairs that match too; an advisory naming no CVE has none. The id is the one grype's DB uses today (Amazon Linux 2's old ALAS-... is ALAS2-...). | Not every CVE an advisory names affects every package it lists, so moving the verdict to its CVEs loses the call the labeler made and invents questions nobody asked. Quality gates run grype with `by-cve`, which reports the match under one CVE instead, and an advisory label that cannot pair it misses every regression on it. | decided 2026-10-21, Alex; aliases 2026-10-26 |

## Justifications

What a label's `justification` can be: the truth about the installed code that makes the verdict
right, with the line the UI shows as the hint's headline. The rule says who found it and how; the
justification says what they found, so the same one comes from many rules (Ubuntu, Red Hat and GitHub
all report `fix-newer`) and a judgement call or a research proposal with no rule still gets a line. It
is evidence that a label is true, never a reason the two scans differ. Each justification is listed
under one verdict, and a label or proposal whose justification is not listed under its verdict is
refused. The author adds the specifics in `note`, a few words: the version, module or file.

The justifications themselves are listed by verdict under `justifications:` in
[vocabulary.yaml](vocabulary.yaml).
