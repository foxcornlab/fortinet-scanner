# `fortinet-scanner`

Local triage for the `Fortinet November 2026 PSIRT` batch, eight `Critical` flaws (`CVSS 9.0` to `9.8`) across `FortiOS`, `FortiManager`, `FortiAnalyzer` and `FortiSASE`, published `10 November 2026`. Give it a product and a version you own, from `get system status` or the `GUI`, and it tells you which of the eight still apply to that box. It never sends a packet, never probes an appliance, never attempts a login.

## `The flaws`

On `10 November 2026` `Fortinet` published `89` advisories covering close to `100` vulnerabilities, found with `AI`-assisted testing (`Fortinet` credits the frontier model `Claude Mythos` in the acknowledgements). The patches themselves shipped in the `October` hardening release, so the details landing on `10 November` is what opened the window, and `Fortinet` warns attackers can now diff a patch and have a working exploit within hours or days. None of the eight is listed as known exploited, and none was in `CISA`'s `KEV` catalog as of `11 November 2026`.

- `CVE-2026-126170` (`FG-IR-26-219`, `9.8`, `CWE-116`): improper encoding in the `FortiManager` / `FortiAnalyzer` `JSON-RPC API`. An unauthenticated attacker may run code or commands through a crafted `HTTP` request, but only when the `JSON API` is enabled on an admin profile. It is disabled by default.
- `CVE-2026-126254` (`FG-IR-26-268`, `9.6`, `CWE-197`): numeric truncation in the `FortiOS` / `FortiSASE BGP` daemon. A configured `iBGP` neighbour may send malformed attributes to all connected routers. Authenticated, not unauthenticated, despite the `9.6`.
- `CVE-2026-126253` (`FG-IR-26-267`, `9.3`, `CWE-305`): authentication bypass in the `FortiOS` / `FortiSASE OSPF` daemon. An unauthenticated attacker on an adjacent network may broadcast forged link state advertisements.
- `CVE-2026-126262` (`FG-IR-26-276`, `9.3`, `CWE-89`): `SQL` injection in the `OFTP` log-reception service (`TCP/514`) of `FortiAnalyzer`, and of `FortiManager` with `FortiAnalyzer` features enabled. Unauthenticated, may run code or commands.
- `CVE-2026-126229` (`FG-IR-26-244`, `9.1`, `CWE-639`): authorization bypass through a user-controlled key in `dmserver`. An authenticated administrator may reach other `VDOM`s through crafted `HTTP` requests.
- `CVE-2026-126261` (`FG-IR-26-275`, `9.0`, `CWE-285`): improper authorization in the `FortiManager FGFM` service (`TCP/541`). An unauthenticated attacker who can reach the `FGFM` port may run code or commands, because the check happens before the registration password is verified.
- `CVE-2026-126260` (`FG-IR-26-274`, `9.0`, `CWE-918`): pre-authentication `SSRF` in the same `OFTP` service as `CVE-2026-126262`.
- `CVE-2026-126259` (`FG-IR-26-273`, `9.0`, `CWE-306`): missing authentication in `FortiOS` high availability. An unauthenticated attacker may run commands as super admin through crafted `HA` packets, but only on clusters using `FGSP` with `standalone-config-sync`, or autoscale.

## `The traps`

| `Signal` | `Grade` | `Why` |
| --- | --- | --- |
| `FortiManager 8.0.1` | `PATCHED` for `CVE-2026-126261`, `VULNERABLE` for `CVE-2026-126170` and `CVE-2026-126229` | **The one-build-does-not-clear-the-batch trap.** `8.0.1` meets the `FGFM` threshold while still falling in the affected range for the `JSON-RPC`, `OFTP` and `dmserver` flaws. Each `CVE` has its own fix table, and this tool grades all eight separately. |
| `FortiManager` / `FortiAnalyzer 8.0.2` | `VULNERABLE` for `CVE-2026-126170` | **The October-fix-level trap.** `8.0.2` is the `October` hardening build and it is still affected. The fix is the upcoming `8.0.3`; until it ships, the workaround is `set rpc-permit none` on the admin profile. |
| `FortiOS 7.0` | `VULNERABLE`, no fix | **The no-fix branch trap.** `7.0` has no fix for the `OSPF` and `HA` flaws (and for `dmserver` on `FM`/`FA`) and must migrate to a fixed release. |
| `FortiAnalyzer 8.0.1` | `VULNERABLE` for `CVE-2026-126262`, `PATCHED` for `CVE-2026-126260` | **The `OFTP` split trap.** The `SSRF` advisory fixes `8.0.1`, the `SQLi` advisory needs `8.0.2` on `FortiAnalyzer`. `FortiManager` needs only `8.0.1` for both. Do not copy one product's fix onto the other. |
| `FortiOS 7.0` for `CVE-2026-126254` | `UNKNOWN` | **The missing-row trap.** The `BGP` advisory lists no `7.0` row at all, while the `OSPF` advisory lists `7.0.1` to `7.0.19` as migrate. This tool does not infer `7.0` status for the `BGP` flaw from the `OSPF` advisory. |
| `FortiManager` / `FortiAnalyzer 7.4` or `7.2` for `CVE-2026-126170` | `NOT-AFFECTED` | **The wrong-branch trap.** The `JSON-RPC` flaw touches only the `8.0` and `7.6` lines. A `7.4` manager needs no upgrade for this `CVE`, even though the same box may be open to the `OFTP` and `dmserver` flaws. |
| `FortiSASE 26.3.1` / `26.3.1_a` | `VULNERABLE`, fix `26.3.2` | `Fortinet` remediated the routing flaws in `26.3.2` with no customer action needed, but `26.3.1` is still open. `26.2` and earlier `25.x` must migrate; `22.4` to `24.4` are not affected. |
| `FortiSASE-Sovereign 26.2` | `PATCHED` | Remediated before release, no action needed. `25.x` must migrate. Do not mix `FortiSASE` and `FortiSASE-Sovereign` tables: they are different products with different fixes. |
| `Cloud` versions for the `OFTP` pair | `UNKNOWN` | The `OFTP` advisories list no `Cloud` rows, so a `Cloud` version is left ungraded for `CVE-2026-126262` and `CVE-2026-126260`, not cleared. |

## `What it checks`

- `One box` (`--product fortios --version 7.4.13`): graded against all eight `CVE`s, per product
- `A get system status line` (`--product fortimanager --version "Version: FortiManager v8.0.1,build..."`): parsed, suffixes like `26.3.1_a` handled
- `Exposure, per flaw` (`--no-json-api`, `--no-ospf`, `--no-ibgp`, `--no-ha-fgsp`, `--no-fgfm`, `--no-oftp`, `--single-vdom`, `--no-fa-features`): a version in range with the prerequisite off grades `NOT-EXPOSED`, not `VULNERABLE`. Unknown exposure is assumed exposed, and the note says so
- `A version file` (`--version-file version.txt`): first line is the version, which may be a full `get system status` line
- `A fleet, offline` (`--inventory-json fleet.json`): a `JSON` list of `{label, product, version}` entries, with optional exposure booleans per box
- `The full table` (`--list`): affected ranges and fixed releases for all eight `CVE`s
- `Machine output` (`--json`): the same grades as `JSON`

```sh
python3 fortinet_scanner.py --product fortios --version 7.4.13
python3 fortinet_scanner.py --product fortimanager --version 8.0.1
python3 fortinet_scanner.py --product fortios --version 7.4.12 --no-ospf --no-ibgp
python3 fortinet_scanner.py --product fortimanager --version 8.0.1 --no-json-api
python3 fortinet_scanner.py --product fortianalyzer --version-file version.txt
python3 fortinet_scanner.py --inventory-json fleet.json
```

```json
[
  {"label": "gate-01", "product": "fortios", "version": "7.4.12"},
  {"label": "mgr-01", "product": "fortimanager", "version": "8.0.1"},
  {"label": "anlz-01", "product": "fortianalyzer", "version": "8.0.1", "oftp": true}
]
```

Exit codes: `0` nothing vulnerable found, `2` vulnerable finding, `1` scan error. `UNKNOWN` does not change the exit code, but it is not clean.

Find your version with `get system status` on the appliance CLI, or from the `GUI` (`System > Firmware` on a `FortiGate`, `System Settings > Dashboard` on `FortiManager` / `FortiAnalyzer`). Paste the version string, not a screenshot.

## `The table`

| `CVE` | `Score` | `Products` | `Fixed in` |
| --- | --- | --- | --- |
| `CVE-2026-126170` | `9.8` | `FM` / `FA` / `Cloud` / `BigData` / `Sovereign` | `8.0.3` * / `7.6.8` / `BigData 7.6.3` * |
| `CVE-2026-126254` | `9.6` | `FortiOS` / `FortiSASE` | `8.0.2` / `7.6.8` / `7.4.13` / `7.2.14` |
| `CVE-2026-126253` | `9.3` | `FortiOS` / `FortiSASE` | `8.0.2` / `7.6.8` / `7.4.13` / `7.2.14` |
| `CVE-2026-126262` | `9.3` | `FA` / `FM` with `FA` features | `FA 8.0.2` / `FM 8.0.1` / `7.6.8` / `7.4.12` / `7.2.13` |
| `CVE-2026-126229` | `9.1` | `FM` / `FA` / `Cloud` | `8.0.2` / `7.6.8` / `7.4.12` / `7.2.13` |
| `CVE-2026-126261` | `9.0` | `FortiManager` | `8.0.1` / `7.6.8` / `7.4.6` / `7.2.9` |
| `CVE-2026-126260` | `9.0` | `FA` / `FM` with `FA` features | `8.0.1` / `7.6.8` / `7.4.12` / `7.2.13` |
| `CVE-2026-126259` | `9.0` | `FortiOS` (`HA`) | `8.0.1` / `7.6.8` / `7.4.13` / `7.2.14` |

\* `8.0.3` and `FA-BigData 7.6.3` were still listed as upcoming when `FG-IR-26-219` was published; use the `rpc-permit none` workaround until they ship. `FortiOS 7.0` and `FM`/`FA 7.0` have no fix for several of these `CVE`s and must migrate.

## `What this tool does not do`

It does not probe a `FortiGate`, `FortiManager` or `FortiAnalyzer` over the network. `Fortinet` versions are not reliably fingerprintable remotely without authentication, so remote probing would guess, and guessing is not triage. It grades version strings you supply from systems you own or are authorised to test. It does not test any of the eight flaws: testing them would mean sending crafted `BGP` attributes, forged `OSPF` advertisements, `FGFM` packets, `OFTP` payloads or `JSON-RPC` requests at a live appliance, which is an attack, not a version check. It does not fetch or use any proof of concept, and it does not scan the network for `Fortinet` installs.

## `Tests`

```sh
python3 -m unittest discover -s tests -v
```

`88` tests, all passing: version parsing in every accepted form (`get system status` lines, `v`-prefix, two-part `FortiSASE` releases, `_a` suffixes, garbage), the grading boundaries for all eight `CVE`s on every product line, the exposure predicates (`NOT-EXPOSED` when a prerequisite is off, assumed exposed when unknown), the traps (`8.0.2` still open to `CVE-2026-126170`, `8.0.1` clearing `FGFM` but not the batch, the `FortiOS 7.0` migrate rows, the `BGP 7.0` missing row, the `OFTP 8.0` split, the `Cloud` `OFTP` unknown), fleet inventory grading, `CLI` exit codes and `JSON` output.

## `Sources`

- `Fortinet PSIRT FG-IR-26-219` (`CVE-2026-126170`), `FG-IR-26-267` (`CVE-2026-126253`), `FG-IR-26-268` (`CVE-2026-126254`), `FG-IR-26-275` (`CVE-2026-126261`), `FG-IR-26-244` (`CVE-2026-126229`), all published `10 November 2026`, read in full `13 November 2026`: exact affected and fixed versions as printed on the pages
- `Fortinet PSIRT FG-IR-26-273` (`CVE-2026-126259`) and `FG-IR-26-276` / `FG-IR-26-274` (`CVE-2026-126262` / `CVE-2026-126260`), corroborated across secondary reporting that re-fetched the live pages and `CSAF` records (`11`–`12 November 2026`)
- `Fortinet` hardening-release post (`21 October 2026`, updated `10 November 2026`): patches shipped `22 October`, details published `10 November`
- `nuclei-templates`, checked `13 November 2026`: no template for `CVE-2026-126170` or `CVE-2026-126253` (both paths `404`); searches returned no template for the other six `CVE`s. Detection coverage found is `Splunk` / `KQL` / `Sigma` rules, not a version triage tool.

Disagreements to note. First, `FG-IR-26-219`'s own page disagrees with itself: the `Impact` field says denial of service while the `Summary` says the attacker may execute unauthorized code or commands; this tool follows the `Summary` and the `CVE` record, which both describe code execution. Second, `CVE-2026-126259` scores `9.0` on the `Fortinet` page, but the `CVE` record vector (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) computes to `9.8` and some trackers list `9.8`; this tool follows the `Fortinet` page's `9.0`. Third, for `CVE-2026-126259` the live page presents `7.6.8` / `7.4.13` / `7.2.14` as upgrades while `Fortinet`'s `CSAF` labels those three builds upcoming; this tool grades them `PATCHED` per the live page and attaches the caveat to the grade. Fourth, one secondary report lists the `FGFM` fix as `8.0.2`; the advisory page and every other source say `8.0.1`, and this tool follows the advisory. Fifth, the `OFTP SSRF` `8.0` fix (`8.0.1` for both products) is single-sourced, and the sibling `SQLi` advisory needs `8.0.2` on `FortiAnalyzer`; a `FortiAnalyzer` on `8.0.1` stays `VULNERABLE` overall through the `SQLi` anyway, so the practical advice is identical: go to `8.0.2`. Sixth, `CVE-2026-126259`'s `8.0` fix is `8.0.1`, not the `8.0.2` that generic batch summaries print for `FortiOS`; the two numbers belong to different advisories. Seventh, no `KEV` entry and no confirmed exploitation as of writing, so this pick rests on the scores and `Fortinet`'s patch-diff warning, not on active exploitation.

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.

## `Thanks to`

- `Fortinet`'s `PSIRT` team and the internal researchers who found these flaws with `AI`-assisted testing
- The secondary researchers who re-fetched the live advisory pages and `CSAF` records and caught the `8.0.1` vs `8.0.2` and upcoming-build discrepancies before this tool shipped

## `Disclaimer`

Educational and defensive use only. This tool grades version strings against a published fix table. It is not a scanner for finding live targets, and it does not exploit anything. Use it on systems you own or are authorised to test.
