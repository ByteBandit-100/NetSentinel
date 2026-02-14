import json
import os


class ScanComparator:

    @staticmethod
    def load_previous_scan(filepath: str):
        if not os.path.exists(filepath):
            return None

        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def compare(old_data: dict, new_data: dict):

        old_ports = {p["port"]: p for p in old_data["open_ports"]}
        new_ports = {p["port"]: p for p in new_data["open_ports"]}

        newly_opened = []
        closed_ports = []
        severity_changed = []

        # Newly opened
        for port in new_ports:
            if port not in old_ports:
                newly_opened.append(new_ports[port])

        # Closed ports
        for port in old_ports:
            if port not in new_ports:
                closed_ports.append(old_ports[port])

        # Severity changes
        for port in new_ports:
            if port in old_ports:
                if new_ports[port]["severity"] != old_ports[port]["severity"]:
                    severity_changed.append({
                        "port": port,
                        "old": old_ports[port]["severity"],
                        "new": new_ports[port]["severity"]
                    })

        return {
            "newly_opened": newly_opened,
            "closed_ports": closed_ports,
            "severity_changed": severity_changed
        }
