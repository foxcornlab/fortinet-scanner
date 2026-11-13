#!/usr/bin/env python3
"""Detection-only triage for the Fortinet November 2026 PSIRT batch.

On 10 November 2026 Fortinet published its monthly PSIRT batch, 89
advisories covering close to 100 vulnerabilities, found with the help
of AI-assisted testing (Fortinet credits the frontier model Claude
Mythos in the acknowledgements). Eight of them are rated Critical,
CVSS 9.0 to 9.8, across FortiOS, FortiManager, FortiAnalyzer and
FortiSASE. None is listed as known exploited, and none was in CISA's
KEV catalog as of 11 November 2026, so this pick rests on the scores
and on Fortinet's own warning that attackers can now diff a patch and
have a working exploit within hours or days, not on active
exploitation. The patches themselves shipped in the October hardening
release, so the details landing on 10 November is what opened the
window.

The eight, each graded against its own fix table:

    CVE-2026-126170 (FG-IR-26-219, 9.8, CWE-116): improper encoding
        in the FortiManager / FortiAnalyzer JSON-RPC API. An
        unauthenticated attacker may run code or commands through a
        crafted HTTP request, but only when the JSON API is enabled
        on an admin profile; it is disabled by default.
    CVE-2026-126254 (FG-IR-26-268, 9.6, CWE-197): numeric
        truncation in the FortiOS / FortiSASE BGP daemon. A
        configured iBGP neighbour may send malformed attributes to
        all connected routers. Authenticated, not unauthenticated,
        despite the 9.6.
    CVE-2026-126253 (FG-IR-26-267, 9.3, CWE-305): authentication
        bypass in the FortiOS / FortiSASE OSPF daemon. An
        unauthenticated attacker on an adjacent network may
        broadcast forged link state advertisements.
    CVE-2026-126262 (FG-IR-26-276, 9.3, CWE-89): SQL injection in
        the OFTP log-reception service (TCP/514) of FortiAnalyzer,
        and of FortiManager with FortiAnalyzer features enabled.
        Unauthenticated, may run code or commands.
    CVE-2026-126229 (FG-IR-26-244, 9.1, CWE-639): authorization
        bypass through a user-controlled key in dmserver. An
        authenticated administrator may reach other VDOMs through
        crafted HTTP requests.
    CVE-2026-126261 (FG-IR-26-275, 9.0, CWE-285): improper
        authorization in the FortiManager FGFM service (TCP/541).
        An unauthenticated attacker who can reach the FGFM port may
        run code or commands, because the check happens before the
        registration password is verified.
    CVE-2026-126260 (FG-IR-26-274, 9.0, CWE-918): pre-authentication
        SSRF in the same OFTP service as CVE-2026-126262.
    CVE-2026-126259 (FG-IR-26-273, 9.0, CWE-306): missing
        authentication in FortiOS high availability. An
        unauthenticated attacker may run commands as super admin
        through crafted HA packets, but only on clusters using FGSP
        with standalone-config-sync, or autoscale.

The traps this tool exists for: one build does not clear the batch.
FortiManager 8.0.1 meets the FGFM threshold for CVE-2026-126261
while still falling in the affected range for the JSON-RPC, OFTP and
dmserver flaws, and FortiManager 8.0.2 is the October fix level that
is still affected by CVE-2026-126170, whose fix is the upcoming
8.0.3. FortiOS 7.0 has no fix for the OSPF and HA flaws and must
migrate. FortiAnalyzer 8.0.1 is fixed for the OFTP SSRF but still
open to the OFTP SQL injection, which needs 8.0.2. Each CVE is
graded separately and the worst grade wins.

This tool sends no traffic, probes no appliance, and attempts no
login. It only compares version strings you supply, from `get
system status` output or the GUI, against the advisory tables. A
VULNERABLE grade means the version is below the fix; it does not
mean the appliance was compromised, and a PATCHED grade does not
prove it was never attacked.

Usage:
    python3 fortinet_scanner.py --product fortios --version 7.4.13
    python3 fortinet_scanner.py --product fortimanager --version 8.0.1
    python3 fortinet_scanner.py --product fortios --version 7.4.12 --no-ospf --no-ibgp
    python3 fortinet_scanner.py --product fortimanager --version 8.0.1 --no-json-api
    python3 fortinet_scanner.py --product fortianalyzer --version-file version.txt
    python3 fortinet_scanner.py --inventory-json fleet.json
    python3 fortinet_scanner.py --list

Exit codes: 0 = nothing vulnerable found, 2 = vulnerable finding,
1 = scan error (missing argument, bad input). UNKNOWN does not change
the exit code, but it is not clean: an unparseable, unlisted, or
disputed version has not been cleared, it has simply not been
graded.
"""

import argparse
import json
import re
import sys
from pathlib import Path

# CVE identifiers, in score order.
CVE_126170 = "CVE-2026-126170"  # 9.8 JSON-RPC injection, FM/FA
CVE_126254 = "CVE-2026-126254"  # 9.6 BGP numeric truncation, FortiOS
CVE_126253 = "CVE-2026-126253"  # 9.3 OSPF auth bypass, FortiOS
CVE_126262 = "CVE-2026-126262"  # 9.3 OFTP SQL injection, FA/FM
CVE_126229 = "CVE-2026-126229"  # 9.1 dmserver authz bypass, FM/FA
CVE_126261 = "CVE-2026-126261"  # 9.0 FGFM improper authz, FM
CVE_126260 = "CVE-2026-126260"  # 9.0 OFTP SSRF, FA/FM
CVE_126259 = "CVE-2026-126259"  # 9.0 FortiOS HA missing auth

ALL_CVES = (
    CVE_126170, CVE_126254, CVE_126253, CVE_126262,
    CVE_126229, CVE_126261, CVE_126260, CVE_126259,
)

PRODUCTS = (
    "fortios",
    "fortisase",
    "fortisase-sovereign",
    "fortimanager",
    "fortianalyzer",
    "fortianalyzer-bigdata",
    "fortimanager-cloud",
    "fortianalyzer-cloud",
)

# Fix-table rows. Each row is (branch, lo, hi, fixed, kind) where
# branch is the (major, minor) line, lo/hi bound the affected range
# inclusive, fixed is the first fixed release on that branch, and
# kind is one of:
#   "fixed"       fixed release exists and is downloadable
#   "upcoming"    fixed release is named but was still upcoming when
#                 the advisory was published; versions in range are
#                 VULNERABLE and the note names the workaround
#   "migrate"     no fix on this branch; fixed is None and every
#                 version in range is VULNERABLE until migration
#   "not-affected" the branch is listed as not affected; fixed is None
#   "remediated"  Fortinet remediated the issue in this branch before
#                 release, so every version on it grades PATCHED
#                 with no action needed
# A version whose (major, minor) branch has no row grades UNKNOWN,
# unless the whole product is out of scope for that CVE, which is
# handled by the CVE tables below (a product with no rows at all for
# a CVE is NOT-AFFECTED for that CVE).
#
# Sources: the five Fortinet PSIRT pages read in full on 13 November
# 2026 (FG-IR-26-219, -267, -268, -275, -244), corroborated by
# Fortinet's 21 October hardening-release post and secondary
# reporting for FG-IR-26-273 (HA), FG-IR-26-276 (OFTP SQLi) and
# FG-IR-26-274 (OFTP SSRF). Disagreements are listed in README.md.

# CVE-2026-126170 (9.8): FM/FA 8.0.0-8.0.2 -> upcoming 8.0.3,
# 7.6.0-7.6.7 -> 7.6.8; 7.4 and 7.2 not affected. Cloud 8.0 starts
# at 8.0.1. FA-BigData 7.6.0-7.6.2 -> upcoming 7.6.3. Sovereign
# 26.2 remediated pre-release; 25.x migrate.
TABLE_126170 = {
    "fortimanager": [
        ((8, 0), (8, 0, 0), (8, 0, 2), (8, 0, 3), "upcoming"),
        ((7, 6), (7, 6, 0), (7, 6, 7), (7, 6, 8), "fixed"),
        ((7, 4), None, None, None, "not-affected"),
        ((7, 2), None, None, None, "not-affected"),
    ],
    "fortianalyzer": [
        ((8, 0), (8, 0, 0), (8, 0, 2), (8, 0, 3), "upcoming"),
        ((7, 6), (7, 6, 0), (7, 6, 7), (7, 6, 8), "fixed"),
        ((7, 4), None, None, None, "not-affected"),
        ((7, 2), None, None, None, "not-affected"),
    ],
    "fortimanager-cloud": [
        ((8, 0), (8, 0, 1), (8, 0, 2), (8, 0, 3), "upcoming"),
        ((7, 6), (7, 6, 0), (7, 6, 7), (7, 6, 8), "fixed"),
        ((7, 4), None, None, None, "not-affected"),
        ((7, 2), None, None, None, "not-affected"),
    ],
    "fortianalyzer-cloud": [
        ((8, 0), (8, 0, 1), (8, 0, 2), (8, 0, 3), "upcoming"),
        ((7, 6), (7, 6, 0), (7, 6, 7), (7, 6, 8), "fixed"),
        ((7, 4), None, None, None, "not-affected"),
        ((7, 2), None, None, None, "not-affected"),
    ],
    "fortianalyzer-bigdata": [
        ((7, 6), (7, 6, 0), (7, 6, 2), (7, 6, 3), "upcoming"),
        ((7, 4), None, None, None, "not-affected"),
        ((7, 2), None, None, None, "not-affected"),
    ],
    "fortisase-sovereign": [
        ((26, 2), None, None, None, "remediated"),
        ((25, 4), (25, 4, 0), (25, 4, 99), None, "migrate"),
        ((25, 3), (25, 3, 0), (25, 3, 99), None, "migrate"),
        # The advisory lists "25.4, 25.3 and 25, all versions" as
        # migrate; "25" is read here as the rest of the 25 line,
        # 25.2/25.1/25.0, since 26.2 is the remediated release and
        # nothing in 25.x is fixed.
        ((25, 2), (25, 2, 0), (25, 2, 99), None, "migrate"),
        ((25, 1), (25, 1, 0), (25, 1, 99), None, "migrate"),
        ((25, 0), (25, 0, 0), (25, 0, 99), None, "migrate"),
    ],
}

# CVE-2026-126254 (9.6) and CVE-2026-126253 (9.3): FortiOS
# 8.0.0-8.0.1 -> 8.0.2, 7.6.0-7.6.7 -> 7.6.8, 7.4.0-7.4.12 ->
# 7.4.13, 7.2.0-7.2.13 -> 7.2.14. FortiSASE 26.3.1/26.3.1_a ->
# remediated in 26.3.2 (no action); 26.2/26.1/25.x migrate;
# 22.4-24.4 not affected. The two advisories share these tables,
# with one difference: FG-IR-26-267 (OSPF) lists FortiOS 7.0.1-7.0.19
# as migrate, while FG-IR-26-268 (BGP) lists no 7.0 row at all.
_FORTIOS_ROUTING = [
    ((8, 0), (8, 0, 0), (8, 0, 1), (8, 0, 2), "fixed"),
    ((7, 6), (7, 6, 0), (7, 6, 7), (7, 6, 8), "fixed"),
    ((7, 4), (7, 4, 0), (7, 4, 12), (7, 4, 13), "fixed"),
    ((7, 2), (7, 2, 0), (7, 2, 13), (7, 2, 14), "fixed"),
]
_FORTISASE_ROUTING = [
    ((26, 3), (26, 3, 1), (26, 3, 1), (26, 3, 2), "fixed"),
    ((26, 2), (26, 2, 0), (26, 2, 99), None, "migrate"),
    ((26, 1), (26, 1, 0), (26, 1, 99), None, "migrate"),
    ((25, 4), (25, 4, 0), (25, 4, 99), None, "migrate"),
    ((25, 3), (25, 3, 0), (25, 3, 99), None, "migrate"),
    ((25, 2), (25, 2, 0), (25, 2, 99), None, "migrate"),
    ((25, 1), (25, 1, 0), (25, 1, 99), None, "migrate"),
    ((24, 4), None, None, None, "not-affected"),
    ((24, 3), None, None, None, "not-affected"),
    ((24, 1), None, None, None, "not-affected"),
    ((23, 4), None, None, None, "not-affected"),
    ((23, 3), None, None, None, "not-affected"),
    ((23, 2), None, None, None, "not-affected"),
    ((23, 1), None, None, None, "not-affected"),
    ((22, 4), None, None, None, "not-affected"),
]
TABLE_126253 = {
    "fortios": _FORTIOS_ROUTING + [
        ((7, 0), (7, 0, 1), (7, 0, 19), None, "migrate"),
    ],
    "fortisase": _FORTISASE_ROUTING,
}
# BGP: same tables, minus the FortiOS 7.0 row (the advisory lists
# none, so 7.0 grades UNKNOWN for this CVE, not migrate).
TABLE_126254 = {
    "fortios": _FORTIOS_ROUTING,
    "fortisase": _FORTISASE_ROUTING,
}

# CVE-2026-126262 (9.3, OFTP SQLi) and CVE-2026-126260 (9.0, OFTP
# SSRF): FortiAnalyzer 8.0.0-8.0.1 -> 8.0.2, 7.6.0-7.6.7 -> 7.6.8,
# 7.4.0-7.4.11 -> 7.4.12, 7.2.0-7.2.12 -> 7.2.13. FortiManager
# (with FortiAnalyzer features enabled) 8.0.0 -> 8.0.1, same
# 7.6/7.4/7.2 fixes. The 8.0 split is the trap: FortiAnalyzer
# needs 8.0.2 for the SQLi, FortiManager needs 8.0.1. For the SSRF
# advisory the reported 8.0 fix is 8.0.1 for both products (single
# source, see README); the per-CVE grading still catches it because
# an 8.0.1 FortiAnalyzer stays VULNERABLE to the SQLi.
_FORTIANALYZER_OFTP = [
    ((8, 0), (8, 0, 0), (8, 0, 1), (8, 0, 2), "fixed"),
    ((7, 6), (7, 6, 0), (7, 6, 7), (7, 6, 8), "fixed"),
    ((7, 4), (7, 4, 0), (7, 4, 11), (7, 4, 12), "fixed"),
    ((7, 2), (7, 2, 0), (7, 2, 12), (7, 2, 13), "fixed"),
]
_FORTIMANAGER_OFTP_126262 = [
    ((8, 0), (8, 0, 0), (8, 0, 0), (8, 0, 1), "fixed"),
    ((7, 6), (7, 6, 0), (7, 6, 7), (7, 6, 8), "fixed"),
    ((7, 4), (7, 4, 0), (7, 4, 11), (7, 4, 12), "fixed"),
    ((7, 2), (7, 2, 0), (7, 2, 12), (7, 2, 13), "fixed"),
]
_FORTIANALYZER_OFTP_126260 = [
    ((8, 0), (8, 0, 0), (8, 0, 1), (8, 0, 1), "fixed"),
    ((7, 6), (7, 6, 0), (7, 6, 7), (7, 6, 8), "fixed"),
    ((7, 4), (7, 4, 0), (7, 4, 11), (7, 4, 12), "fixed"),
    ((7, 2), (7, 2, 0), (7, 2, 12), (7, 2, 13), "fixed"),
]
_FORTIMANAGER_OFTP_126260 = [
    ((8, 0), (8, 0, 0), (8, 0, 0), (8, 0, 1), "fixed"),
    ((7, 6), (7, 6, 0), (7, 6, 7), (7, 6, 8), "fixed"),
    ((7, 4), (7, 4, 0), (7, 4, 11), (7, 4, 12), "fixed"),
    ((7, 2), (7, 2, 0), (7, 2, 12), (7, 2, 13), "fixed"),
]
TABLE_126262 = {
    "fortianalyzer": _FORTIANALYZER_OFTP,
    "fortimanager": _FORTIMANAGER_OFTP_126262,
}
TABLE_126260 = {
    "fortianalyzer": _FORTIANALYZER_OFTP_126260,
    "fortimanager": _FORTIMANAGER_OFTP_126260,
}

# CVE-2026-126229 (9.1, dmserver): FM/FA/Cloud 8.0.0-8.0.1 ->
# 8.0.2, 7.6.0-7.6.7 -> 7.6.8, 7.4.0-7.4.11 -> 7.4.12,
# 7.2.0-7.2.12 -> 7.2.13, 7.0 all versions migrate. Cloud ranges
# start one patch later on 8.0 (8.0.1 only), 7.4 (7.4.1) and 7.2
# (7.2.1).
_DMSERVER = [
    ((8, 0), (8, 0, 0), (8, 0, 1), (8, 0, 2), "fixed"),
    ((7, 6), (7, 6, 0), (7, 6, 7), (7, 6, 8), "fixed"),
    ((7, 4), (7, 4, 0), (7, 4, 11), (7, 4, 12), "fixed"),
    ((7, 2), (7, 2, 0), (7, 2, 12), (7, 2, 13), "fixed"),
    ((7, 0), (7, 0, 0), (7, 0, 99), None, "migrate"),
]
_DMSERVER_CLOUD = [
    ((8, 0), (8, 0, 1), (8, 0, 1), (8, 0, 2), "fixed"),
    ((7, 6), (7, 6, 0), (7, 6, 7), (7, 6, 8), "fixed"),
    ((7, 4), (7, 4, 1), (7, 4, 11), (7, 4, 12), "fixed"),
    ((7, 2), (7, 2, 1), (7, 2, 12), (7, 2, 13), "fixed"),
    ((7, 0), (7, 0, 0), (7, 0, 99), None, "migrate"),
]
TABLE_126229 = {
    "fortimanager": _DMSERVER,
    "fortianalyzer": _DMSERVER,
    "fortimanager-cloud": _DMSERVER_CLOUD,
    "fortianalyzer-cloud": _DMSERVER_CLOUD,
}

# CVE-2026-126261 (9.0, FGFM): FortiManager only. 8.0.0 -> 8.0.1,
# 7.6.0-7.6.7 -> 7.6.8, 7.4.0-7.4.5 -> 7.4.6, 7.2.0-7.2.8 ->
# 7.2.9. No 7.0 row is listed, so 7.0 grades UNKNOWN.
TABLE_126261 = {
    "fortimanager": [
        ((8, 0), (8, 0, 0), (8, 0, 0), (8, 0, 1), "fixed"),
        ((7, 6), (7, 6, 0), (7, 6, 7), (7, 6, 8), "fixed"),
        ((7, 4), (7, 4, 0), (7, 4, 5), (7, 4, 6), "fixed"),
        ((7, 2), (7, 2, 0), (7, 2, 8), (7, 2, 9), "fixed"),
    ],
}

# CVE-2026-126259 (9.0, HA missing auth): FortiOS only.
# 8.0.0 -> 8.0.1, 7.6.0-7.6.7 -> 7.6.8, 7.4.0-7.4.12 -> 7.4.13,
# 7.2.0-7.2.13 -> 7.2.14, 7.0 all versions migrate. Caveat: the
# live advisory page presents 7.6.8/7.4.13/7.2.14 as upgrades while
# Fortinet's CSAF labels those three builds "upcoming"; confirm
# availability before treating a PATCHED grade as installed.
# A virtual patch, FG-VD-61445.0day, is in FMWP db update 26.082.
TABLE_126259 = {
    "fortios": [
        ((8, 0), (8, 0, 0), (8, 0, 0), (8, 0, 1), "fixed"),
        ((7, 6), (7, 6, 0), (7, 6, 7), (7, 6, 8), "fixed"),
        ((7, 4), (7, 4, 0), (7, 4, 12), (7, 4, 13), "fixed"),
        ((7, 2), (7, 2, 0), (7, 2, 13), (7, 2, 14), "fixed"),
        ((7, 0), (7, 0, 0), (7, 0, 99), None, "migrate"),
    ],
}

TABLES = {
    CVE_126170: TABLE_126170,
    CVE_126254: TABLE_126254,
    CVE_126253: TABLE_126253,
    CVE_126262: TABLE_126262,
    CVE_126229: TABLE_126229,
    CVE_126261: TABLE_126261,
    CVE_126260: TABLE_126260,
    CVE_126259: TABLE_126259,
}

# Products whose scope for a CVE is genuinely unknown, as opposed
# to not affected: the OFTP advisories list no Cloud rows, so a
# Cloud version grades UNKNOWN for those two CVEs, not clean.
SCOPE_UNKNOWN = {
    CVE_126262: {"fortianalyzer-cloud", "fortimanager-cloud"},
    CVE_126260: {"fortianalyzer-cloud", "fortimanager-cloud"},
}

# Exposure predicates, one per CVE. The key is the exposure flag
# name used by the CLI and the inventory JSON. A missing flag means
# unknown, and unknown is assumed exposed, with the note saying so.
# False means the prerequisite is not present, which grades
# NOT-EXPOSED instead of VULNERABLE.
EXPOSURE_FLAGS = {
    CVE_126170: "json_api",
    CVE_126254: "ibgp",
    CVE_126253: "ospf",
    CVE_126262: "oftp",
    CVE_126229: "multi_vdom",
    CVE_126261: "fgfm",
    CVE_126260: "oftp",
    CVE_126259: "ha_fgsp",
}
EXPOSURE_LABELS = {
    "json_api": "the JSON API is enabled on an admin profile",
    "ibgp": "a configured iBGP neighbour exists",
    "ospf": "the OSPF daemon is reachable",
    "oftp": "the OFTP service (TCP/514) is reachable",
    "multi_vdom": "the box runs more than one VDOM",
    "fgfm": "the FGFM port (TCP/541) is reachable",
    "ha_fgsp": "HA FGSP with standalone-config-sync, or autoscale, is configured",
}
# Negated labels, used in NOT-EXPOSED notes, and the CLI flag that
# asserts each prerequisite is absent.
EXPOSURE_NEGATED = {
    "json_api": "the JSON API is not enabled on any admin profile",
    "ibgp": "no configured iBGP neighbour exists",
    "ospf": "the OSPF daemon is not reachable",
    "oftp": "the OFTP service (TCP/514) is not reachable",
    "multi_vdom": "the box runs a single VDOM",
    "fgfm": "the FGFM port (TCP/541) is not reachable",
    "ha_fgsp": "neither HA FGSP with standalone-config-sync nor autoscale is configured",
}
EXPOSURE_CLI_FLAGS = {
    "json_api": "--no-json-api",
    "ibgp": "--no-ibgp",
    "ospf": "--no-ospf",
    "oftp": "--no-oftp",
    "multi_vdom": "--single-vdom",
    "fgfm": "--no-fgfm",
    "ha_fgsp": "--no-ha-fgsp",
}
# FortiManager needs FortiAnalyzer features enabled for the OFTP
# pair to apply at all. Unknown is assumed on, with a note.
FM_OFTP_FLAG = "fa_features"

CVE_SCORES = {
    CVE_126170: "9.8",
    CVE_126254: "9.6",
    CVE_126253: "9.3",
    CVE_126262: "9.3",
    CVE_126229: "9.1",
    CVE_126261: "9.0",
    CVE_126260: "9.0",
    CVE_126259: "9.0",
}
CVE_TITLES = {
    CVE_126170: "JSON-RPC API injection (unauthenticated RCE)",
    CVE_126254: "BGP daemon numeric truncation (iBGP neighbour)",
    CVE_126253: "OSPF daemon authentication bypass (unauthenticated)",
    CVE_126262: "OFTP SQL injection (unauthenticated RCE)",
    CVE_126229: "dmserver authorization bypass (authenticated, cross-VDOM)",
    CVE_126261: "FGFM improper authorization (unauthenticated RCE)",
    CVE_126260: "OFTP SSRF (unauthenticated)",
    CVE_126259: "HA missing authentication (unauthenticated, super admin)",
}

_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def parse_version(text):
    """Return a (major, minor, patch) tuple, or None.

    Accepts a bare version like `7.6.8`, a two-part FortiSASE
    release like `25.1`, a `get system status` line like `Version:
    FortiOS v7.4.13,build2716`, and suffixed builds like
    `26.3.1_a`. A suffix such as `_a` is dropped for comparison:
    26.3.1 and 26.3.1_a are the same affected build in the
    advisories. A version with no patch number is padded with 0.
    """
    if not isinstance(text, str):
        return None
    match = _VERSION_RE.search(text)
    if not match:
        return None
    major, minor, patch = match.groups()
    return (int(major), int(minor), int(patch) if patch is not None else 0)


def format_version(version):
    return ".".join(str(part) for part in version)


def _find_row(rows, version):
    """Return the table row for a version's (major, minor) branch."""
    branch = version[:2]
    for row in rows:
        if row[0] == branch:
            return row
    return None


def _grade_row(version, row, cve, product, exposure):
    """Grade one version against one fix-table row."""
    _branch, lo, hi, fixed, kind = row
    flag = EXPOSURE_FLAGS[cve]
    if kind == "not-affected":
        return {
            "grade": "NOT-AFFECTED",
            "fixed": None,
            "note": f"{product} {format_version(version)} is on a "
            f"branch the advisory lists as not affected by {cve}",
        }
    if kind == "remediated":
        return {
            "grade": "PATCHED",
            "fixed": format_version(version),
            "note": f"Fortinet remediated {cve} in {product} "
            f"{version[0]}.{version[1]} before release; customers "
            "do not need to perform any action",
        }
    if version < lo:
        return {
            "grade": "NOT-AFFECTED",
            "fixed": format_version(fixed) if fixed else None,
            "note": f"{product} {format_version(version)} is below "
            f"the affected range for {cve} "
            f"({format_version(lo)} through {format_version(hi)})",
        }
    if kind == "migrate":
        if version <= hi:
            return {
                "grade": "VULNERABLE",
                "fixed": None,
                "note": f"{product} {format_version(version)} is in "
                f"the affected range for {cve} and there is no fix "
                "on this branch; migrate to a fixed release",
            }
        return {
            "grade": "UNKNOWN",
            "fixed": None,
            "note": f"{product} {format_version(version)} is above "
            f"the listed range for {cve} on a branch with no fix; "
            "the advisory lists no newer build, so confirm with "
            "Fortinet before trusting it",
        }
    if version >= fixed:
        note = (
            f"{product} {format_version(version)} is at or above "
            f"the fixed release {format_version(fixed)} for {cve}"
        )
        if kind == "upcoming":
            note += (
                f". {format_version(fixed)} was still listed as "
                "upcoming when the advisory was published, so "
                "confirm the build is actually downloadable before "
                "treating this as installed"
            )
        if cve == CVE_126259:
            note += (
                ". Note: Fortinet's CSAF labels the 7.6.8/7.4.13/"
                "7.2.14 builds upcoming while the live advisory "
                "page presents them as upgrades; confirm "
                "availability"
            )
        return {"grade": "PATCHED", "fixed": format_version(fixed), "note": note}
    if exposure is False:
        return {
            "grade": "NOT-EXPOSED",
            "fixed": format_version(fixed),
            "note": f"{product} {format_version(version)} is in the "
            f"affected range for {cve}, but "
            f"{EXPOSURE_NEGATED[flag]}, so the vulnerable code is "
            "not reachable on this install",
        }
    note = (
        f"{product} {format_version(version)} is in the affected "
        f"range for {cve} ({format_version(lo)} through "
        f"{format_version(hi)}); upgrade to "
        f"{format_version(fixed)} or later"
    )
    if kind == "upcoming":
        note += (
            f". {format_version(fixed)} was still listed as "
            "upcoming when the advisory was published; until it "
            "ships, apply the vendor workaround"
        )
        if cve == CVE_126170:
            note += (
                " (set rpc-permit none on the admin profile, "
                "`config system admin profile`)"
            )
    if exposure is None:
        note += (
            f". Exposure is unknown, so this grade assumes "
            f"{EXPOSURE_LABELS[flag]}; pass "
            f"{EXPOSURE_CLI_FLAGS[flag]} if you know it is not"
        )
    return {"grade": "VULNERABLE", "fixed": format_version(fixed), "note": note}


def grade_one_cve(product, version, cve, exposure):
    """Grade one product version against one CVE's table."""
    if product in SCOPE_UNKNOWN.get(cve, ()):
        return {
            "grade": "UNKNOWN",
            "fixed": None,
            "note": f"the {cve} advisory lists no {product} rows "
            "for the OFTP service; confirm with Fortinet before "
            "treating this install as clear",
        }
    table = TABLES[cve]
    if product not in table:
        return {
            "grade": "NOT-AFFECTED",
            "fixed": None,
            "note": f"{cve} does not apply to {product}; the "
            "advisory covers other Fortinet products",
        }
    rows = table[product]
    row = _find_row(rows, version)
    if row is None:
        branches = ", ".join(
            f"{r[0][0]}.{r[0][1]}" for r in rows if r[3] is not None or r[4] != "not-affected"
        )
        return {
            "grade": "UNKNOWN",
            "fixed": None,
            "note": f"{product} {format_version(version)} is on a "
            f"branch the {cve} advisory lists no range for; known "
            f"branches are {branches or 'none listed'}. It has not "
            "been cleared, only left ungraded",
        }
    return _grade_row(version, row, cve, product, exposure)


def grade(product, version_text, exposure=None, fa_features=None):
    """Grade one product version against the whole batch.

    exposure is a dict of flag name -> True/False/None, keyed by
    EXPOSURE_FLAGS values. fa_features applies to FortiManager for
    the OFTP pair only: False means FortiAnalyzer features are off,
    so those two CVEs do not apply. Returns per-CVE grades and an
    overall verdict.
    """
    exposure = exposure or {}
    parsed = parse_version(version_text)
    if parsed is None:
        return {
            "product": product,
            "version": version_text,
            "overall": "UNKNOWN",
            "cves": {
                cve: {
                    "grade": "UNKNOWN",
                    "fixed": None,
                    "note": f"version {version_text!r} does not "
                    "parse as a Fortinet release like 7.6.8. A "
                    "`get system status` line or a bare version "
                    "is expected",
                }
                for cve in ALL_CVES
            },
        }
    version = parsed
    cves = {}
    for cve in ALL_CVES:
        # FortiManager without FortiAnalyzer features is not in
        # scope for the OFTP pair at all.
        if (
            cve in (CVE_126262, CVE_126260)
            and product == "fortimanager"
            and fa_features is False
        ):
            cves[cve] = {
                "grade": "NOT-AFFECTED",
                "fixed": None,
                "note": f"{cve} affects FortiManager only with "
                "FortiAnalyzer features enabled, and they are off "
                "on this manager",
            }
            continue
        flag = EXPOSURE_FLAGS[cve]
        result = grade_one_cve(product, version, cve, exposure.get(flag))
        if (
            cve in (CVE_126262, CVE_126260)
            and product == "fortimanager"
            and fa_features is None
            and result["grade"] == "VULNERABLE"
        ):
            result["note"] += (
                ". FortiAnalyzer-features status is unknown, so "
                "this grade assumes they are enabled; pass "
                "--no-fa-features if they are off"
            )
        cves[cve] = result
    order = ["VULNERABLE", "UNKNOWN", "NOT-EXPOSED", "PATCHED", "NOT-AFFECTED"]
    overall = min(
        (result["grade"] for result in cves.values()),
        key=order.index,
    )
    return {
        "product": product,
        "version": format_version(version),
        "overall": overall,
        "cves": cves,
    }


def grade_inventory(entries):
    """Grade a fleet inventory: list of {label, product, version} dicts."""
    results = []
    for entry in entries:
        label = entry.get("label", entry.get("host", "?"))
        product = entry.get("product")
        version = entry.get("version")
        if product not in PRODUCTS:
            results.append(
                {
                    "label": label,
                    "overall": "UNKNOWN",
                    "note": f"unknown product {product!r}; expected "
                    f"one of {', '.join(PRODUCTS)}",
                }
            )
            continue
        if version is None:
            results.append(
                {
                    "label": label,
                    "overall": "UNKNOWN",
                    "note": "no version in this inventory entry",
                }
            )
            continue
        exposure = {
            key: entry[key]
            for key in EXPOSURE_LABELS
            if key in entry
        }
        result = grade(
            product,
            version,
            exposure=exposure,
            fa_features=entry.get("fa_features"),
        )
        result["label"] = label
        results.append(result)
    return results


def print_table():
    print("Fortinet November 2026 PSIRT batch, published 10 November 2026")
    print()
    print("CVE              Score  Products            Fixed in")
    print("CVE-2026-126170  9.8    FM/FA/Cloud/BigData  8.0.3 * / 7.6.8")
    print("CVE-2026-126254  9.6    FortiOS/FortiSASE   8.0.2 / 7.6.8 / 7.4.13 / 7.2.14")
    print("CVE-2026-126253  9.3    FortiOS/FortiSASE   8.0.2 / 7.6.8 / 7.4.13 / 7.2.14")
    print("CVE-2026-126262  9.3    FA / FM w/ FA feat.  FA 8.0.2 / FM 8.0.1 / 7.6.8 / 7.4.12 / 7.2.13")
    print("CVE-2026-126229  9.1    FM/FA/Cloud         8.0.2 / 7.6.8 / 7.4.12 / 7.2.13")
    print("CVE-2026-126261  9.0    FortiManager        8.0.1 / 7.6.8 / 7.4.6 / 7.2.9")
    print("CVE-2026-126260  9.0    FA / FM w/ FA feat.  8.0.1 / 7.6.8 / 7.4.12 / 7.2.13")
    print("CVE-2026-126259  9.0    FortiOS (HA)        8.0.1 / 7.6.8 / 7.4.13 / 7.2.14")
    print()
    print("* 8.0.3 (and FA-BigData 7.6.3) were still listed as")
    print("  upcoming when FG-IR-26-219 was published; use the")
    print("  rpc-permit none workaround until they ship.")
    print("FortiOS 7.0 and FM/FA 7.0 have no fix for several of")
    print("these CVEs and must migrate. One build does not clear")
    print("the batch: grade every CVE separately.")


def _emit(result, as_json):
    if as_json:
        print(json.dumps(result, indent=2))
        return
    label = result.get("label")
    if label:
        print(f"[{label}]")
    print(f"product: {result.get('product', '?')}")
    print(f"version: {result.get('version', '?')}")
    print(f"overall: {result['overall']}")
    for cve, detail in result.get("cves", {}).items():
        print(f"  {cve}: {detail['grade']} - {detail['note']}")
    for note in result.get("notes", []):
        print(f"  note: {note}")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Detection-only triage for the Fortinet November "
        "2026 PSIRT batch (8 critical CVEs, FG-IR-26-219/244/267/"
        "268/273/274/275/276)."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--version", help="product version string, "
                       "e.g. 7.6.8 or a `get system status` line")
    group.add_argument("--version-file", help="file holding a version string")
    group.add_argument("--inventory-json",
                       help="JSON list of {label, product, version} entries")
    group.add_argument("--list", action="store_true",
                       help="print the CVE table and exit")
    parser.add_argument("--product", choices=PRODUCTS,
                        help="Fortinet product the version belongs to")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable JSON output")
    parser.add_argument("--json-api", action=argparse.BooleanOptionalAction,
                        default=None, help="JSON API enabled (CVE-2026-126170)")
    parser.add_argument("--ospf", action=argparse.BooleanOptionalAction,
                        default=None, help="OSPF daemon reachable (CVE-2026-126253)")
    parser.add_argument("--ibgp", action=argparse.BooleanOptionalAction,
                        default=None, help="configured iBGP neighbour (CVE-2026-126254)")
    parser.add_argument("--ha-fgsp", action=argparse.BooleanOptionalAction,
                        default=None, help="HA FGSP + standalone-config-sync or "
                        "autoscale (CVE-2026-126259)")
    parser.add_argument("--fgfm", action=argparse.BooleanOptionalAction,
                        default=None, help="FGFM port reachable (CVE-2026-126261)")
    parser.add_argument("--oftp", action=argparse.BooleanOptionalAction,
                        default=None, help="OFTP service reachable "
                        "(CVE-2026-126262, CVE-2026-126260)")
    parser.add_argument("--fa-features", action=argparse.BooleanOptionalAction,
                        default=None, help="FortiAnalyzer features enabled on "
                        "a FortiManager (OFTP pair)")
    parser.add_argument("--multi-vdom", action=argparse.BooleanOptionalAction,
                        default=None, help="box runs more than one VDOM "
                        "(CVE-2026-126229)")
    args = parser.parse_args(argv)

    if args.list:
        print_table()
        return 0

    if args.product is None and args.inventory_json is None:
        parser.error("--product is required unless --list or "
                     "--inventory-json is given")

    exposure = {
        "json_api": args.json_api,
        "ospf": args.ospf,
        "ibgp": args.ibgp,
        "ha_fgsp": args.ha_fgsp,
        "fgfm": args.fgfm,
        "oftp": args.oftp,
        "multi_vdom": args.multi_vdom,
    }

    try:
        if args.version:
            result = grade(
                args.product, args.version,
                exposure=exposure, fa_features=args.fa_features,
            )
        elif args.version_file:
            result = grade(
                args.product,
                Path(args.version_file).read_text().strip(),
                exposure=exposure, fa_features=args.fa_features,
            )
        elif args.inventory_json:
            entries = json.loads(Path(args.inventory_json).read_text())
            results = grade_inventory(entries)
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                for entry_result in results:
                    _emit(entry_result, False)
                    print()
            return 2 if any(
                r["overall"] == "VULNERABLE" for r in results
            ) else 0
        else:  # pragma: no cover - argparse enforces one option
            parser.error("no scan mode given")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    _emit(result, args.json)
    return 2 if result["overall"] == "VULNERABLE" else 0


if __name__ == "__main__":
    raise SystemExit(main())
