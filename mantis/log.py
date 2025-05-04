# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025 Federico Fantini

import logging

class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': '\033[94m',     # blue
        'INFO': '\033[92m',      # green
        'WARNING': '\033[93m',   # yellow
        'ERROR': '\033[91m',     # red
        'CRITICAL': '\033[1;91m' # bold red
    }
    RESET = '\033[0m'

    def format(self, record):
        color = self.COLORS.get(record.levelname, self.RESET)
        message = super().format(record)
        return f"{color}{message}{self.RESET}"

# Setup
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter(
    '%(asctime)s [%(levelname)s] (%(threadName)s) %(name)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
))

logger.setLevel(logging.INFO)
logger.addHandler(handler)
logger.propagate = False