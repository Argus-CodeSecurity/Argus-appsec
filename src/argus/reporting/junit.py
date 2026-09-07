"""JUnit XML reporter for CI systems (spec §35)."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from argus.core.models import ScanResult
from argus.core.plugin import Reporter, reporter


@reporter
class JUnitReporter(Reporter):
    name = "junit"
    extension = "xml"
    description = "JUnit XML format for CI test result integration."

    def render(self, result: ScanResult) -> str:
        testsuite = ET.Element("testsuite")
        testsuite.set("name", "argus")
        testsuite.set("tests", str(len(result.findings)))
        testsuite.set("failures", str(len(result.findings)))
        for f in result.findings:
            case = ET.SubElement(testsuite, "testcase")
            case.set("name", f"{f.rule_id} ({f.location.as_ref()})")
            case.set("classname", f.scanner)
            fail = ET.SubElement(case, "failure")
            fail.set("message", f.title)
            fail.text = f.description or f.why_vulnerable or f.title
        return ET.tostring(testsuite, encoding="unicode")
