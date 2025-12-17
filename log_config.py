import logging
import os

# Define the log file name and directory
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "recon.log")

def setup_logging():
    """
    Configures the logging system for console output and file logging.
    """
    # 1. Create the logs directory if it doesn't exist
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)

    # 2. Get the root logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO) # Set the minimum level for all handlers

    # 3. Define the formatters
    # Detailed format for the log file (includes timestamp and source)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)-8s - (%(name)s:%(lineno)d) - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    # Simple format for console (less cluttered)
    console_formatter = logging.Formatter(
        '[%-8s] - %(message)s'
    )

    # 4. File Handler (writes logs to a file)
    file_handler = logging.FileHandler(LOG_FILE, mode='a')
    file_handler.setLevel(logging.DEBUG) # Log all levels to the file
    file_handler.setFormatter(file_formatter)

    # 5. Console Handler (prints logs to the terminal)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO) # Log INFO and above to console
    console_handler.setFormatter(console_formatter)

    # 6. Add handlers to the logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    logger.info("--- Recon session started ---")

    # Return a specific logger for easy use in other modules
    return logging.getLogger("RECON")