import logging
import os
import sys
from rich.logging import RichHandler

def setup_logging(level=logging.INFO):
    """
    Configures logging for the entire application.
    Supports console (Rich) and file logging.
    If RECON_LOG_QUIET is set, console logging is suppressed (for JSON mode).
    """
    logger = logging.getLogger("RECON")
    logger.setLevel(level)

    # Prevent duplicate handlers
    if logger.handlers:
        return logger

    # Console Handler (Rich)
    quiet_mode = os.getenv('RECON_LOG_QUIET', '0') == '1'
    if not quiet_mode:
        console_handler = RichHandler(
            rich_tracebacks=True,
            markup=True,
            show_time=True,
            show_path=False
        )
        console_handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(console_handler)

    # File Handler
    try:
        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)
        file_handler = logging.FileHandler(os.path.join(log_dir, "recon.log"))
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        ))
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"Warning: Could not setup file logging: {e}")

    return logger