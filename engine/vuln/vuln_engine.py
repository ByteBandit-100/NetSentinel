# engine/vuln/vuln_engine.py

from engine.vuln.vuln_database import VULN_DB
from engine.vuln.rule_engine import RuleEngine


class VulnerabilityEngine:

    @staticmethod
    def analyze(service, version, port, banner):

        findings = []

        for rule in VULN_DB:

            result = RuleEngine.evaluate(
                rule,
                port=port,
                service=service,
                version=version,
                banner=banner
            )

            if not result:
                continue

            confidence = result["confidence_score"]

            if confidence >= 80:
                level = "CONFIRMED"
            elif confidence >= 60:
                level = "LIKELY"
            else:
                level = "POSSIBLE"

            findings.append({
                "id": rule["id"],
                "name": rule["name"],
                "severity": rule["severity"],
                "confidence": level,
                "confidence_score": confidence,
                "description": rule.get("description", "")
            })

        return findings