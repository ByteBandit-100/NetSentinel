import ipaddress


class InputValidator:

    @staticmethod
    def validate_ip(ip: str):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError(f"Invalid IP address: {ip}")

    @staticmethod
    def validate_port(port: int):
        if not 1 <= port <= 65535:
            raise ValueError(f"Invalid port number: {port}")

    @staticmethod
    def validate_port_range(start: int, end: int):
        if start > end:
            raise ValueError("Start port cannot be greater than end port")

        InputValidator.validate_port(start)
        InputValidator.validate_port(end)
