import re


class VersionDetector:

    PATTERNS = {
        "apache": r"Apache/?([\d\.]+)",
        "nginx": r"nginx/?([\d\.]+)",
        "openssh": r"OpenSSH[_ ]([\d\.p]+)",
        "microsoft-iis": r"Microsoft-IIS/?([\d\.]+)",
        "vsftpd": r"vsftpd ([\d\.]+)"
    }

    @classmethod
    def detect(cls, banner: str):

        if not banner:
            return None

        for name, pattern in cls.PATTERNS.items():
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                if match.groups():
                    return f"{name.capitalize()} {match.group(1)}"
                return name.capitalize()

        # 🔥 fallback: return short cleaned banner
        cleaned = banner.replace("\r", "").replace("\n", " ")
        return cleaned[:40] if cleaned else None