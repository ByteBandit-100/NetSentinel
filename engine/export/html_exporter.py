import os
from datetime import datetime
from config import REPORT_BASE_DIR

class HTMLExporter:

    @staticmethod
    def export(data: dict, target: str) -> str:

        html_dir = os.path.join(REPORT_BASE_DIR, "html_reports")
        os.makedirs(html_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{target}_{timestamp}.html"
        filepath = os.path.join(html_dir, filename)

        html_content = HTMLExporter.generate_html(data)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        return filepath

    @staticmethod
    def generate_html(data: dict) -> str:

        rows = ""

        for port in data["open_ports"]:
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

            <h1>NetSentinel Scan Report</h1>

            <h3>Target: {data['target']}</h3>
            <p>Port Range: {data['start_port']} - {data['end_port']}</p>
            <p>Total Scanned: {data['total_scanned']}</p>
            <p>Time Taken: {data['scan_time']} seconds</p>

            <h2>Open Ports</h2>

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
