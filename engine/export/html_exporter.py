import os
import re
from datetime import datetime
from config import REPORT_BASE_DIR

class HTMLExporter:

    @staticmethod
    def export(data: dict, target: str) -> str:

        html_dir = os.path.join(REPORT_BASE_DIR, "html_reports")
        os.makedirs(html_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        safe_target = re.sub(r'[^\w\.-]', '_', target)
        filename = f"{safe_target}_{timestamp}.html"
        filepath = os.path.join(html_dir, filename)


        html_content = HTMLExporter.generate_html(data)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        return filepath

    @staticmethod
    def generate_html(data: dict) -> str:

        rows = ""

        for host in data["results"]:
            target = host["target"]
            ports = host["open_ports"]

            # Host Header Row
            rows += f"""
            <tr style="background-color:#222;">
                <td colspan="4" style="font-weight:bold; color:#00bfff;">
                    Host: {target}
                </td>
            </tr>
            """

            for port in ports:
                severity = port.get("severity", "low")

                color = {
                    "high": "#ff4d4d",
                    "medium": "#ffa500",
                    "low": "#4CAF50"
                }.get(severity, "#4CAF50")

                rows += f"""
                <tr>
                    <td>{port['port']}</td>
                    <td>{port.get('service', 'unknown')}</td>
                    <td>{port.get('banner', 'N/A')}</td>
                    <td style="color:{color}; font-weight:bold;">
                        {severity.upper()}
                    </td>
                </tr>
                """

        return f"""
        <html>
        <head>
            <title>NetSentinel Scan Report</title>
            <style>
                body {{
                    font-family: Arial;
                    background-color: #1e1e1e;
                    color: white;
                    padding: 20px;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                }}
                th, td {{
                    border: 1px solid #444;
                    padding: 10px;
                    text-align: left;
                }}
                th {{
                    background-color: #333;
                }}
            </style>
        </head>
        <body>

            <h1>NetSentinel Network Scan Report</h1>

            <p>Scan Type: {data['scan_type']}</p>
            <p>Port Range: {data['start_port']} - {data['end_port']}</p>
            <p>Targets Scanned: {data['targets_scanned']}</p>
            <p>Time Taken: {data['scan_time']} seconds</p>

            <h2>Results</h2>

            <table>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Banner</th>
                    <th>Severity</th>
                </tr>
                {rows}
            </table>

        </body>
        </html>
        """