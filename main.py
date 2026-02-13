from config import APP_NAME, VERSION
from engine.core.logger import LoggerFactory


def main():
    logger = LoggerFactory.get_logger("app", "scan_logs")

    print(f"{APP_NAME} v{VERSION} starting...")

    logger.info("Application started successfully.")
    logger.info("Logger system initialized.")


if __name__ == "__main__":
    main()
