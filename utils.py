"""
ReconX - Logger Module
Provides colored, leveled logging throughout the tool.
"""

import logging
import sys

# ANSI color codes
COLORS = {
    "DEBUG":    "\033[94m",   # Blue
    "INFO":     "\033[92m",   # Green
    "WARNING":  "\033[93m",   # Yellow
    "ERROR":    "\033[91m",   # Red
    "CRITICAL": "\033[95m",   # Magenta
    "RESET":    "\033[0m",
    "DIM":      "\033[2m",
    "BOLD":     "\033[1m",
}


class ColorFormatter(logging.Formatter):
    """Custom formatter that adds color to log output."""

    FORMATS = {
        logging.DEBUG:    COLORS["DEBUG"]    + "[DEBUG]   %(message)s" + COLORS["RESET"],
        logging.INFO:     COLORS["INFO"]     + "%(message)s"            + COLORS["RESET"],
        logging.WARNING:  COLORS["WARNING"]  + "[WARN]    %(message)s" + COLORS["RESET"],
        logging.ERROR:    COLORS["ERROR"]    + "[ERROR]   %(message)s" + COLORS["RESET"],
        logging.CRITICAL: COLORS["CRITICAL"] + "[CRITICAL] %(message)s" + COLORS["RESET"],
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


_logger = None


def setup_logger(verbose: bool = False, quiet: bool = False) -> logging.Logger:
    """Initialize and configure the global logger."""
    global _logger

    logger = logging.getLogger("reconx")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(ColorFormatter())
        logger.addHandler(handler)

    _logger = logger
    return logger


def get_logger() -> logging.Logger:
    """Return the global logger, initializing with defaults if needed."""
    global _logger
    if _logger is None:
        return setup_logger()
    return _logger
