# engine/vuln/rule_engine.py

class RuleEngine:

    @staticmethod
    def evaluate(rule, port, service, version, banner):

        match = rule.get("match", {})
        confidence = 0

        # Port match (weak evidence)
        if match.get("port") == port:
            confidence += 30
        else:
            return None

        # Service match
        if match.get("service") and service:
            if match["service"].lower() in service.lower():
                confidence += 25

        # Version match
        if version and match.get("version_contains"):
            for v in match["version_contains"]:
                if v.lower() in version.lower():
                    confidence += 35

        # Banner match
        if banner and match.get("version_contains"):
            banner_str = banner.decode(errors="ignore") if isinstance(banner, bytes) else str(banner)
            for v in match["version_contains"]:
                if v.lower() in banner_str.lower():
                    confidence += 10

        if confidence < 40:
            return None

        return {
            "confidence_score": confidence
        }