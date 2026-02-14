import socket


class ServiceMapper:

    @staticmethod
    def get_service_name(port: int) -> str:
        try:
            return socket.getservbyport(port)
        except:
            return "unknown"
