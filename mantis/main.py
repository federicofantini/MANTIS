# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025 Federico Fantini


from .log import logger

import os
import sys
import asyncio
import dotenv


# ALARM SYSTEM STATUS
def enable_alarm_system():
    dotenv_file = dotenv.find_dotenv()
    if not dotenv_file:
        logger.error(".env file not found!")
        sys.exit(1)
    os.environ["ALARM_SYSTEM"] = "on"
    dotenv.set_key(dotenv_file, "ALARM_SYSTEM", os.environ["ALARM_SYSTEM"])

def disable_alarm_system():
    dotenv_file = dotenv.find_dotenv()
    if not dotenv_file:
        logger.error(".env file not found!")
        sys.exit(1)
    os.environ["ALARM_SYSTEM"] = "off"
    dotenv.set_key(dotenv_file, "ALARM_SYSTEM", os.environ["ALARM_SYSTEM"])

def is_alarm_system_enabled():
    return True if os.getenv("ALARM_SYSTEM", "") == "on" else False



if __name__ == "__main__":
    dotenv_file = dotenv.find_dotenv()
    if not dotenv_file:
        logger.error(".env file not found!")
        sys.exit(1)
    dotenv.load_dotenv()
    mode = os.getenv("MODE", "")

    enabled_alarm_system = is_alarm_system_enabled()

    # Creates instance of Mantis based on the chosen modality and start Mantis.loop()
    if mode == 'xmpp':
        from .xmpp.mantis import Mantis as MantisXMPP

        jid = os.getenv("XMPP_JID", "")
        password = os.getenv("XMPP_PASSWORD", "")
        admin_jid = os.getenv("XMPP_ADMIN_USERNAME", "")
        enabled = os.getenv("XMPP_ALLOWED_USERNAMES", "")
        allowed_jids = [x.strip() for x in enabled.split(",") if x.strip()]

        if not jid or not password:
            logger.error("❌ JID and PASSWORD must be set in the .env file")
            exit(1)

        xmpp = MantisXMPP(jid, password, admin_jid, allowed_jids, enabled_alarm_system)
        xmpp.register_plugin("xep_0030")  # Service Discovery
        xmpp.register_plugin("xep_0199")  # XMPP Ping
        xmpp.register_plugin("xep_0380")  # Explicit Message Encryption
        
        try:
            import slixmpp_omemo
            xmpp.register_plugin("xep_0384", module=slixmpp_omemo)  # OMEMO
            xmpp.register_plugin("xep_0454")  # OMEMO Media sharing
            xmpp.register_plugin("xep_0363")  # Upload HTTP File
        except Exception:
            logger.exception("And error occured when loading omemo plugins.")
            sys.exit(1)
        
        xmpp.connect()
        asyncio.get_event_loop().run_until_complete(xmpp.disconnected)

    elif mode == 'matrix':
        from .matrix.mantis import Mantis as MantisMatrix
        username = os.getenv("MATRIX_USERNAME", "")
        password = os.getenv("MATRIX_PASSWORD", "")
        admin_username = os.getenv("MATRIX_ADMIN_USERNAME", "")
        enabled = os.getenv("MATRIX_ALLOWED_USERNAMES", "")
        allowed_usernames = [x.strip() for x in enabled.split(",") if x.strip()]
        
        if not username or not password:
            logger.error("❌ USERNAME and PASSWORD must be set in the .env file")
            exit(1)
        
        matrix = MantisMatrix(username, password, admin_username, allowed_usernames, enabled_alarm_system)
        asyncio.get_event_loop().run_until_complete(matrix.loop())
    else:
        logger.error(f"Mode {mode} not recognized, exiting...")