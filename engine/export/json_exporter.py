import json
import os
from datetime import datetime
from config import REPORT_BASE_DIR

class JSONExporter:

    @staticmethod
    def export(data: dict, target: str) -> str:
        json_dir = os.path.join(REPORT_BASE_DIR, "json_reports")
        os.makedirs(json_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        safe_target = target.replace("/", "_")
        filename = f"{safe_target}_{timestamp}.json"
        filepath = os.path.join(json_dir, filename)


        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

        return filepath
