class SeverityClassifier:

    HIGH_RISK_PORTS = [21, 23, 25, 110, 445]
    MEDIUM_RISK_PORTS = [80, 8080, 3306]

    @staticmethod
    def classify(port: int, banner: str = None) -> str:

        if port in SeverityClassifier.HIGH_RISK_PORTS:
            return "high"

        if port in SeverityClassifier.MEDIUM_RISK_PORTS:
            return "medium"

        if banner:
            banner_lower = banner.lower()
            if "apache/2.2" in banner_lower:
                return "high"
            if "php/5" in banner_lower:
                return "high"

        return "low"
