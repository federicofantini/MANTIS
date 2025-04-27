# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025 Federico Fantini

import logging

logger = logging.getLogger(__name__)

logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s [%(levelname)s] (%(threadName)s) %(name)s - %(message)s',
    datefmt="%Y-%m-%d %H:%M:%S",
)