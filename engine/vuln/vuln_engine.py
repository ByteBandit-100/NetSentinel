from engine.vuln.vuln_database import VULN_DB

class VulnerabilityEngine:

    @staticmethod
    def analyze(service, version, port, banner):

        findings = []

        service = (service or "").lower()
        version = (version or "").lower()
        banner = str(banner or "").lower()

        for vuln in VULN_DB:

            # Match by port
            if vuln.get("port") and vuln["port"] == port:
                findings.append(vuln)
                continue

            # Match by service name
            if vuln.get("service") and vuln["service"].lower() in service:
                findings.append(vuln)
                continue

            # Match by version substring
            if vuln.get("version") and vuln["version"].lower() in version:
                findings.append(vuln)
                continue

            # Match by banner keyword
            if vuln.get("keyword") and vuln["keyword"].lower() in banner:
                findings.append(vuln)
                continue

        return findings