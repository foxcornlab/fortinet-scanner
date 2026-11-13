#!/usr/bin/env python3
"""Tests for fortinet_scanner.py.

Covers version parsing in every accepted form, the grading
boundaries for all eight CVEs in the November 2026 Fortinet PSIRT
batch on every product line, the exposure predicates, the traps
(8.0.1 FGFM vs 8.0.2 JSON-RPC, 8.0.2 still affected by 126170,
FortiOS 7.0 migrate, FortiAnalyzer 8.0.1 OFTP split, BGP 7.0
unlisted, upcoming 8.0.3), inventory grading, CLI exit codes and
JSON output.
"""

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import fortinet_scanner as scanner

C170 = scanner.CVE_126170
C254 = scanner.CVE_126254
C253 = scanner.CVE_126253
C262 = scanner.CVE_126262
C229 = scanner.CVE_126229
C261 = scanner.CVE_126261
C260 = scanner.CVE_126260
C259 = scanner.CVE_126259


class ParseVersionTests(unittest.TestCase):
    def test_bare_version(self):
        self.assertEqual(scanner.parse_version("7.6.8"), (7, 6, 8))

    def test_two_part_version(self):
        self.assertEqual(scanner.parse_version("25.1"), (25, 1, 0))

    def test_get_system_status_line(self):
        self.assertEqual(
            scanner.parse_version("Version: FortiOS v7.4.13,build2716"),
            (7, 4, 13),
        )

    def test_fortisase_suffix(self):
        self.assertEqual(scanner.parse_version("26.3.1_a"), (26, 3, 1))

    def test_fortisase_dotted_suffix(self):
        self.assertEqual(scanner.parse_version("25.1.a"), (25, 1, 0))

    def test_v_prefix(self):
        self.assertEqual(scanner.parse_version("v8.0.2"), (8, 0, 2))

    def test_garbage(self):
        self.assertIsNone(scanner.parse_version("not a version"))

    def test_empty(self):
        self.assertIsNone(scanner.parse_version(""))


def grade(product, version, **kw):
    return scanner.grade(product, version, **kw)


class JsonRpc170Tests(unittest.TestCase):
    def test_fm_802_still_vulnerable(self):
        # The 8.0.2 trap: October fix level, still affected, fix is
        # the upcoming 8.0.3.
        result = grade("fortimanager", "8.0.2")
        self.assertEqual(result["cves"][C170]["grade"], "VULNERABLE")
        self.assertEqual(result["cves"][C170]["fixed"], "8.0.3")
        self.assertIn("upcoming", result["cves"][C170]["note"])

    def test_fm_803_patched_with_upcoming_caveat(self):
        result = grade("fortimanager", "8.0.3")
        self.assertEqual(result["cves"][C170]["grade"], "PATCHED")
        self.assertIn("upcoming", result["cves"][C170]["note"])

    def test_fm_768_patched(self):
        result = grade("fortimanager", "7.6.8")
        self.assertEqual(result["cves"][C170]["grade"], "PATCHED")

    def test_fm_767_vulnerable(self):
        result = grade("fortimanager", "7.6.7")
        self.assertEqual(result["cves"][C170]["grade"], "VULNERABLE")

    def test_fm_74_not_affected(self):
        # The 7.4/7.2 not-affected trap: no upgrade needed for 126170.
        result = grade("fortimanager", "7.4.5")
        self.assertEqual(result["cves"][C170]["grade"], "NOT-AFFECTED")

    def test_fm_72_not_affected(self):
        result = grade("fortimanager", "7.2.9")
        self.assertEqual(result["cves"][C170]["grade"], "NOT-AFFECTED")

    def test_fm_70_unknown(self):
        result = grade("fortimanager", "7.0.5")
        self.assertEqual(result["cves"][C170]["grade"], "UNKNOWN")

    def test_fa_cloud_801_vulnerable(self):
        result = grade("fortianalyzer-cloud", "8.0.1")
        self.assertEqual(result["cves"][C170]["grade"], "VULNERABLE")

    def test_fa_cloud_800_not_affected(self):
        # Cloud 8.0 range starts at 8.0.1; 8.0.0 does not exist there.
        result = grade("fortianalyzer-cloud", "8.0.0")
        self.assertEqual(result["cves"][C170]["grade"], "NOT-AFFECTED")

    def test_bigdata_762_vulnerable(self):
        result = grade("fortianalyzer-bigdata", "7.6.2")
        self.assertEqual(result["cves"][C170]["grade"], "VULNERABLE")
        self.assertEqual(result["cves"][C170]["fixed"], "7.6.3")

    def test_bigdata_763_patched(self):
        result = grade("fortianalyzer-bigdata", "7.6.3")
        self.assertEqual(result["cves"][C170]["grade"], "PATCHED")

    def test_sovereign_262_patched_no_action(self):
        result = grade("fortisase-sovereign", "26.2")
        self.assertEqual(result["cves"][C170]["grade"], "PATCHED")

    def test_sovereign_254_migrate(self):
        result = grade("fortisase-sovereign", "25.4")
        self.assertEqual(result["cves"][C170]["grade"], "VULNERABLE")
        self.assertIsNone(result["cves"][C170]["fixed"])
        self.assertIn("migrate", result["cves"][C170]["note"])

    def test_json_api_off_not_exposed(self):
        result = grade(
            "fortimanager", "8.0.2", exposure={"json_api": False}
        )
        self.assertEqual(result["cves"][C170]["grade"], "NOT-EXPOSED")

    def test_json_api_unknown_assumes_exposed(self):
        result = grade("fortimanager", "8.0.2")
        self.assertEqual(result["cves"][C170]["grade"], "VULNERABLE")
        self.assertIn("unknown", result["cves"][C170]["note"].lower())

    def test_fortios_not_in_scope(self):
        result = grade("fortios", "7.4.12")
        self.assertEqual(result["cves"][C170]["grade"], "NOT-AFFECTED")


class RoutingTests(unittest.TestCase):
    def test_osfp_fortios_801_vulnerable(self):
        result = grade("fortios", "8.0.1")
        self.assertEqual(result["cves"][C253]["grade"], "VULNERABLE")

    def test_ospf_fortios_802_patched(self):
        result = grade("fortios", "8.0.2")
        self.assertEqual(result["cves"][C253]["grade"], "PATCHED")

    def test_bgp_fortios_802_patched(self):
        result = grade("fortios", "8.0.2")
        self.assertEqual(result["cves"][C254]["grade"], "PATCHED")

    def test_fortios_7413_patched_both(self):
        result = grade("fortios", "7.4.13")
        self.assertEqual(result["cves"][C253]["grade"], "PATCHED")
        self.assertEqual(result["cves"][C254]["grade"], "PATCHED")

    def test_fortios_7412_vulnerable_both(self):
        result = grade("fortios", "7.4.12")
        self.assertEqual(result["cves"][C253]["grade"], "VULNERABLE")
        self.assertEqual(result["cves"][C254]["grade"], "VULNERABLE")

    def test_fortios_70_ospf_migrate(self):
        result = grade("fortios", "7.0.10")
        self.assertEqual(result["cves"][C253]["grade"], "VULNERABLE")
        self.assertIsNone(result["cves"][C253]["fixed"])
        self.assertIn("migrate", result["cves"][C253]["note"])

    def test_fortios_70_bgp_unknown(self):
        # FG-IR-26-268 lists no 7.0 row: do not infer from OSPF.
        result = grade("fortios", "7.0.10")
        self.assertEqual(result["cves"][C254]["grade"], "UNKNOWN")

    def test_fortios_700_below_ospf_range(self):
        # Advisory range starts at 7.0.1, not 7.0.0.
        result = grade("fortios", "7.0.0")
        self.assertEqual(result["cves"][C253]["grade"], "NOT-AFFECTED")

    def test_fortisase_2631_vulnerable(self):
        result = grade("fortisase", "26.3.1")
        self.assertEqual(result["cves"][C253]["grade"], "VULNERABLE")
        self.assertEqual(result["cves"][C254]["grade"], "VULNERABLE")

    def test_fortisase_2631_a_vulnerable(self):
        result = grade("fortisase", "26.3.1_a")
        self.assertEqual(result["cves"][C253]["grade"], "VULNERABLE")

    def test_fortisase_2632_patched(self):
        result = grade("fortisase", "26.3.2")
        self.assertEqual(result["cves"][C253]["grade"], "PATCHED")
        self.assertEqual(result["cves"][C254]["grade"], "PATCHED")

    def test_fortisase_262_migrate(self):
        result = grade("fortisase", "26.2")
        self.assertEqual(result["cves"][C253]["grade"], "VULNERABLE")
        self.assertIsNone(result["cves"][C253]["fixed"])

    def test_fortisase_244_not_affected(self):
        result = grade("fortisase", "24.4")
        self.assertEqual(result["cves"][C253]["grade"], "NOT-AFFECTED")
        self.assertEqual(result["cves"][C254]["grade"], "NOT-AFFECTED")

    def test_no_ibgp_not_exposed(self):
        result = grade("fortios", "7.4.12", exposure={"ibgp": False})
        self.assertEqual(result["cves"][C254]["grade"], "NOT-EXPOSED")
        # OSPF still vulnerable: the flags are per-CVE.
        self.assertEqual(result["cves"][C253]["grade"], "VULNERABLE")

    def test_no_ospf_not_exposed(self):
        result = grade("fortios", "7.4.12", exposure={"ospf": False})
        self.assertEqual(result["cves"][C253]["grade"], "NOT-EXPOSED")


class Ha259Tests(unittest.TestCase):
    def test_fortios_800_vulnerable(self):
        result = grade("fortios", "8.0.0")
        self.assertEqual(result["cves"][C259]["grade"], "VULNERABLE")
        self.assertEqual(result["cves"][C259]["fixed"], "8.0.1")

    def test_fortios_801_patched(self):
        result = grade("fortios", "8.0.1")
        self.assertEqual(result["cves"][C259]["grade"], "PATCHED")

    def test_fortios_768_patched_with_csaf_caveat(self):
        result = grade("fortios", "7.6.8")
        self.assertEqual(result["cves"][C259]["grade"], "PATCHED")
        self.assertIn("CSAF", result["cves"][C259]["note"])

    def test_fortios_70_migrate(self):
        result = grade("fortios", "7.0.5")
        self.assertEqual(result["cves"][C259]["grade"], "VULNERABLE")
        self.assertIsNone(result["cves"][C259]["fixed"])

    def test_no_ha_fgsp_not_exposed(self):
        result = grade("fortios", "7.4.12", exposure={"ha_fgsp": False})
        self.assertEqual(result["cves"][C259]["grade"], "NOT-EXPOSED")

    def test_fm_not_in_scope(self):
        result = grade("fortimanager", "7.6.7")
        self.assertEqual(result["cves"][C259]["grade"], "NOT-AFFECTED")


class Fgfm261Tests(unittest.TestCase):
    def test_fm_800_vulnerable(self):
        result = grade("fortimanager", "8.0.0")
        self.assertEqual(result["cves"][C261]["grade"], "VULNERABLE")
        self.assertEqual(result["cves"][C261]["fixed"], "8.0.1")

    def test_fm_801_patched(self):
        # The 8.0.1 trap: 8.0.1 IS the FGFM fix, despite one
        # secondary report saying 8.0.2.
        result = grade("fortimanager", "8.0.1")
        self.assertEqual(result["cves"][C261]["grade"], "PATCHED")

    def test_fm_745_vulnerable(self):
        result = grade("fortimanager", "7.4.5")
        self.assertEqual(result["cves"][C261]["grade"], "VULNERABLE")

    def test_fm_746_patched(self):
        result = grade("fortimanager", "7.4.6")
        self.assertEqual(result["cves"][C261]["grade"], "PATCHED")

    def test_fm_728_vulnerable(self):
        result = grade("fortimanager", "7.2.8")
        self.assertEqual(result["cves"][C261]["grade"], "VULNERABLE")

    def test_fm_729_patched(self):
        result = grade("fortimanager", "7.2.9")
        self.assertEqual(result["cves"][C261]["grade"], "PATCHED")

    def test_fm_70_unknown(self):
        # No 7.0 row in the FGFM advisory.
        result = grade("fortimanager", "7.0.5")
        self.assertEqual(result["cves"][C261]["grade"], "UNKNOWN")

    def test_no_fgfm_not_exposed(self):
        result = grade("fortimanager", "8.0.0", exposure={"fgfm": False})
        self.assertEqual(result["cves"][C261]["grade"], "NOT-EXPOSED")

    def test_fa_not_in_scope(self):
        result = grade("fortianalyzer", "7.6.7")
        self.assertEqual(result["cves"][C261]["grade"], "NOT-AFFECTED")


class OftpTests(unittest.TestCase):
    def test_fa_801_sqli_vulnerable_ssrf_patched(self):
        # The OFTP 8.0 split: 8.0.1 fixes the SSRF but not the SQLi.
        result = grade("fortianalyzer", "8.0.1")
        self.assertEqual(result["cves"][C262]["grade"], "VULNERABLE")
        self.assertEqual(result["cves"][C260]["grade"], "PATCHED")

    def test_fa_802_patched_both(self):
        result = grade("fortianalyzer", "8.0.2")
        self.assertEqual(result["cves"][C262]["grade"], "PATCHED")
        self.assertEqual(result["cves"][C260]["grade"], "PATCHED")

    def test_fm_800_vulnerable_both(self):
        result = grade("fortimanager", "8.0.0")
        self.assertEqual(result["cves"][C262]["grade"], "VULNERABLE")
        self.assertEqual(result["cves"][C260]["grade"], "VULNERABLE")

    def test_fm_801_patched_both(self):
        result = grade("fortimanager", "8.0.1")
        self.assertEqual(result["cves"][C262]["grade"], "PATCHED")
        self.assertEqual(result["cves"][C260]["grade"], "PATCHED")

    def test_fa_7412_patched(self):
        result = grade("fortianalyzer", "7.4.12")
        self.assertEqual(result["cves"][C262]["grade"], "PATCHED")
        self.assertEqual(result["cves"][C260]["grade"], "PATCHED")

    def test_fa_7411_vulnerable(self):
        result = grade("fortianalyzer", "7.4.11")
        self.assertEqual(result["cves"][C262]["grade"], "VULNERABLE")
        self.assertEqual(result["cves"][C260]["grade"], "VULNERABLE")

    def test_fm_no_fa_features_not_affected(self):
        result = grade(
            "fortimanager", "7.6.7", fa_features=False
        )
        self.assertEqual(result["cves"][C262]["grade"], "NOT-AFFECTED")
        self.assertEqual(result["cves"][C260]["grade"], "NOT-AFFECTED")

    def test_fm_fa_features_unknown_assumes_on(self):
        result = grade("fortimanager", "7.6.7")
        self.assertEqual(result["cves"][C262]["grade"], "VULNERABLE")
        self.assertIn("unknown", result["cves"][C262]["note"].lower())

    def test_no_oftp_not_exposed(self):
        result = grade("fortianalyzer", "7.6.7", exposure={"oftp": False})
        self.assertEqual(result["cves"][C262]["grade"], "NOT-EXPOSED")
        self.assertEqual(result["cves"][C260]["grade"], "NOT-EXPOSED")

    def test_cloud_oftp_unknown(self):
        # The OFTP advisories list no Cloud rows: unknown, not clean.
        result = grade("fortianalyzer-cloud", "7.6.7")
        self.assertEqual(result["cves"][C262]["grade"], "UNKNOWN")
        self.assertEqual(result["cves"][C260]["grade"], "UNKNOWN")


class Dmserver229Tests(unittest.TestCase):
    def test_fm_801_vulnerable(self):
        result = grade("fortimanager", "8.0.1")
        self.assertEqual(result["cves"][C229]["grade"], "VULNERABLE")
        self.assertEqual(result["cves"][C229]["fixed"], "8.0.2")

    def test_fm_802_patched(self):
        result = grade("fortimanager", "8.0.2")
        self.assertEqual(result["cves"][C229]["grade"], "PATCHED")

    def test_fm_7412_patched(self):
        result = grade("fortimanager", "7.4.12")
        self.assertEqual(result["cves"][C229]["grade"], "PATCHED")

    def test_fm_7411_vulnerable(self):
        result = grade("fortimanager", "7.4.11")
        self.assertEqual(result["cves"][C229]["grade"], "VULNERABLE")

    def test_fm_70_migrate(self):
        result = grade("fortimanager", "7.0.5")
        self.assertEqual(result["cves"][C229]["grade"], "VULNERABLE")
        self.assertIsNone(result["cves"][C229]["fixed"])

    def test_cloud_800_not_affected(self):
        # Cloud 8.0 range starts at 8.0.1.
        result = grade("fortimanager-cloud", "8.0.0")
        self.assertEqual(result["cves"][C229]["grade"], "NOT-AFFECTED")

    def test_cloud_740_not_affected(self):
        # Cloud 7.4 range starts at 7.4.1.
        result = grade("fortimanager-cloud", "7.4.0")
        self.assertEqual(result["cves"][C229]["grade"], "NOT-AFFECTED")

    def test_single_vdom_not_exposed(self):
        result = grade(
            "fortimanager", "7.6.7", exposure={"multi_vdom": False}
        )
        self.assertEqual(result["cves"][C229]["grade"], "NOT-EXPOSED")


class OverallTests(unittest.TestCase):
    def test_cross_cve_trap_fm_801(self):
        # 8.0.1 clears FGFM but stays open to 126170, 126262/126260
        # (FM 8.0.1 is patched for OFTP, but 126170 needs 8.0.3)
        # and 126229 (needs 8.0.2). Overall must be VULNERABLE.
        result = grade("fortimanager", "8.0.1")
        self.assertEqual(result["overall"], "VULNERABLE")
        self.assertEqual(result["cves"][C261]["grade"], "PATCHED")
        self.assertEqual(result["cves"][C170]["grade"], "VULNERABLE")
        self.assertEqual(result["cves"][C229]["grade"], "VULNERABLE")
        self.assertEqual(result["cves"][C262]["grade"], "PATCHED")

    def test_fully_patched_fortios(self):
        result = grade("fortios", "8.0.2")
        self.assertEqual(result["overall"], "PATCHED")

    def test_fully_patched_fm(self):
        result = grade("fortimanager", "8.0.3")
        self.assertEqual(result["overall"], "PATCHED")

    def test_garbage_version(self):
        result = grade("fortios", "FortiOS")
        self.assertEqual(result["overall"], "UNKNOWN")
        for detail in result["cves"].values():
            self.assertEqual(detail["grade"], "UNKNOWN")

    def test_unknown_branch(self):
        result = grade("fortios", "6.4.0")
        self.assertEqual(result["overall"], "UNKNOWN")
        self.assertEqual(result["cves"][C253]["grade"], "UNKNOWN")


class InventoryTests(unittest.TestCase):
    def test_inventory_mixed(self):
        entries = [
            {"label": "gate-01", "product": "fortios", "version": "7.4.12"},
            {"label": "mgr-01", "product": "fortimanager", "version": "8.0.3"},
            {"label": "bad-01", "product": "fortigate", "version": "7.4.12"},
            {"label": "noversion", "product": "fortios"},
        ]
        results = scanner.grade_inventory(entries)
        self.assertEqual(results[0]["overall"], "VULNERABLE")
        self.assertEqual(results[1]["overall"], "PATCHED")
        self.assertEqual(results[2]["overall"], "UNKNOWN")
        self.assertEqual(results[3]["overall"], "UNKNOWN")

    def test_inventory_exposure_flags(self):
        entries = [
            {
                "label": "gate-01",
                "product": "fortios",
                "version": "7.4.12",
                "ospf": False,
                "ibgp": False,
                "ha_fgsp": False,
            }
        ]
        results = scanner.grade_inventory(entries)
        self.assertEqual(results[0]["overall"], "NOT-EXPOSED")
        self.assertEqual(results[0]["cves"][C253]["grade"], "NOT-EXPOSED")
        self.assertEqual(results[0]["cves"][C254]["grade"], "NOT-EXPOSED")
        self.assertEqual(results[0]["cves"][C259]["grade"], "NOT-EXPOSED")


class CliTests(unittest.TestCase):
    def run_cli(self, argv):
        out = io.StringIO()
        with redirect_stdout(out):
            code = scanner.main(argv)
        return code, out.getvalue()

    def test_list(self):
        code, out = self.run_cli(["--list"])
        self.assertEqual(code, 0)
        for cve in scanner.ALL_CVES:
            self.assertIn(cve, out)

    def test_version_vulnerable_exit_2(self):
        code, out = self.run_cli(
            ["--product", "fortios", "--version", "7.4.12"]
        )
        self.assertEqual(code, 2)
        self.assertIn("VULNERABLE", out)

    def test_version_patched_exit_0(self):
        code, out = self.run_cli(
            ["--product", "fortios", "--version", "8.0.2"]
        )
        self.assertEqual(code, 0)
        self.assertIn("PATCHED", out)

    def test_version_json(self):
        code, out = self.run_cli(
            ["--product", "fortimanager", "--version", "8.0.1", "--json"]
        )
        self.assertEqual(code, 2)
        data = json.loads(out)
        self.assertEqual(data["overall"], "VULNERABLE")
        self.assertEqual(data["cves"][C261]["grade"], "PATCHED")
        self.assertEqual(data["cves"][C170]["grade"], "VULNERABLE")

    def test_version_file(self):
        with tempfile.NamedTemporaryFile(
            "w", suffix=".txt", delete=False
        ) as handle:
            handle.write("Version: FortiOS v7.4.13,build2716\n")
            path = handle.name
        code, out = self.run_cli(
            ["--product", "fortios", "--version-file", path]
        )
        self.assertEqual(code, 0)
        self.assertIn("7.4.13", out)

    def test_inventory_json_cli(self):
        entries = [
            {"label": "a", "product": "fortios", "version": "7.4.12"},
            {"label": "b", "product": "fortios", "version": "8.0.2"},
        ]
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False
        ) as handle:
            json.dump(entries, handle)
            path = handle.name
        code, out = self.run_cli(["--inventory-json", path])
        self.assertEqual(code, 2)
        self.assertIn("[a]", out)
        self.assertIn("[b]", out)

    def test_missing_product_errors(self):
        with self.assertRaises(SystemExit) as ctx:
            scanner.main(["--version", "7.4.12"])
        self.assertEqual(ctx.exception.code, 2)

    def test_bad_product_errors(self):
        with self.assertRaises(SystemExit) as ctx:
            scanner.main(
                ["--product", "fortigate", "--version", "7.4.12"]
            )
        self.assertEqual(ctx.exception.code, 2)

    def test_no_json_api_flag(self):
        code, out = self.run_cli(
            [
                "--product", "fortimanager", "--version", "8.0.2",
                "--no-json-api",
            ]
        )
        self.assertEqual(code, 0)
        self.assertIn("NOT-EXPOSED", out)


if __name__ == "__main__":
    unittest.main()
