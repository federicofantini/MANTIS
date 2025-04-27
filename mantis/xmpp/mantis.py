from ..log import logger
from ..alarm_system import AlarmSystem
from ..main import enable_alarm_system, disable_alarm_system, is_alarm_system_enabled

import re
import sys
import asyncio
from typing import Dict, Literal, Optional, Union

from slixmpp_omemo import XEP_0384

from slixmpp import ClientXMPP, JID
from slixmpp.stanza import Message
from slixmpp.types import MessageTypes
from slixmpp.xmlstream.handler import CoroutineCallback
from slixmpp.xmlstream.matcher import MatchXPath


class Mantis(ClientXMPP):
    cmd_prefix: str = "/"

    def __init__(self, jid: str, password: str, admin_jid: str, allowed_jids: list, alarm_system_enabled: bool):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        ClientXMPP.__init__(self, jid, password)
        self.jid = jid
        self.admin_jid = admin_jid
        self.allowed_jids = allowed_jids
        self.add_event_handler("session_start", self.start)
        self.prefix_re: re.Pattern = re.compile(r"^%s" % self.cmd_prefix)
        self.cmd_re: re.Pattern = re.compile(
            r"^%s(?P<command>\w+)(?:\s+(?P<args>.*))?" % self.cmd_prefix
        )
        self.register_handler(
            CoroutineCallback(
                "Messages",
                MatchXPath(f"{{{self.default_ns}}}message"),
                self._message_handler,
            )
        )
        self.alarm_system = AlarmSystem(self)

    def start(self, _: Dict) -> None:
        self.send_presence()
        self.get_roster()

        if is_alarm_system_enabled():
            self.alarm_system.start()

    async def _send_plain_message(self, mto: JID, mtype: Optional[MessageTypes], body):
        msg = self.make_message(mto=mto, mtype=mtype)
        msg["body"] = body
        return msg.send()
    
    async def _send_encrypted_message(
        self,
        mto: JID,
        mtype: Literal["chat", "normal"],
        data: Union[Message, str]
    ) -> None:
        """
        Helper to send encrypted messages.

        Args:
            mto: The recipient JID.
            mtype: The message type.
            data: Either the message stanza to encrypt or the text content.
        """

        xep_0384: XEP_0384 = self["xep_0384"]

        if isinstance(data, str):
            msg_body = data
            msg = self.make_message(mto=mto, mtype=mtype)
            msg["body"] = msg_body

        msg.set_to(mto)
        msg.set_from(self.jid)

        # It might be a good idea to strip everything bot the body from the stanza, since some things might
        # break when echoed.
        messages, encryption_errors = await xep_0384.encrypt_message(msg, mto)

        if len(encryption_errors) > 0:
            logger.info(f"There were non-critical errors during encryption: {encryption_errors}")

        for namespace, message in messages.items():
            message["eme"]["namespace"] = namespace
            message["eme"]["name"] = self["xep_0380"].mechanisms[namespace]
            message.send()

    def _check_admin(self, message_jid):
        ret = message_jid == self.admin_jid
        logger.info(f"check admin:{ret}    [Admin={self.admin_jid}, Allowed_users={self.allowed_jids}, Message_jid={message_jid}]")
        return ret
    
    def _check_allowed_user(self, message_jid):
        ret = message_jid in [self.admin_jid] + self.allowed_jids
        logger.info(f"check allowed user:{ret}    [Admin={self.admin_jid}, Allowed_users={self.allowed_jids}, Message_jid={message_jid}]")
        return ret

    async def _message_handler(self, stanza: Message) -> None:
        xep_0384: XEP_0384 = self["xep_0384"]

        message_jid = f"{stanza['from'].user}@{stanza['from'].domain}"
        
        if not self._check_allowed_user(message_jid):
            logger.warning(f"Message from not allowed user: {message_jid}")
            return

        mto = stanza["from"]
        mtype = stanza["type"]
        if mtype not in { "chat", "normal" }:
            return

        namespace = xep_0384.is_encrypted(stanza)
        if namespace is None:
            if not stanza["body"]:
                # This is the case for things like read markers, ignore those.
                return

            await self._send_plain_message(
                mto,
                mtype,
                f"Unencrypted message or unsupported message encryption: {stanza['body']}"
            )
            return

        logger.info(f"Message in namespace {namespace} received: {stanza}")

        try:
            message, device_information = await xep_0384.decrypt_message(stanza)

            logger.info(f"Information about sender: {device_information}")

            if not message["body"]:
                # This is the case for things like read markers, ignore those.
                return
            
            if self._is_command(message["body"]):
                await self._handle_command(message_jid, mto, mtype, message["body"])
            else:
                await self._send_encrypted_message(
                    mto, mtype, "No command found in your message, please see available commands with /help."
                )
        except Exception as e:
            logger.exception(e)

    async def _handle_command(
        self, message_jid: str, mto: JID, mtype: Optional[MessageTypes], body: Optional[str]
    ) -> None:
        match = self.cmd_re.match(body)
        if match is None:
            return
        groups = match.groupdict()
        cmd: str = groups["command"]
        args: list = groups['args'].split(" ") if groups['args'] else []
        
        match cmd:
            # ALLOWED USERS + ADMIN
            case "help":
                await self._cmd_help(mto, mtype)
            case "take_picture":
                await self._cmd_take_picture(mto, mtype)
            case "record_video":
                await self._cmd_record_video(mto, mtype, args)
            # ADMIN
            case "exit":
                if self._check_admin(message_jid):
                    await self._cmd_exit(mto, mtype)
            case "enable_alarm_system":
                if self._check_admin(message_jid):
                    await self._cmd_enable_alarm_system(mto, mtype)
            case "disable_alarm_system":
                if self._check_admin(message_jid):
                    await self._cmd_disable_alarm_system(mto, mtype)
            case "is_alarm_system_enabled":
                if self._check_admin(message_jid):
                    await self._cmd_is_alarm_system_enabled(mto, mtype)
            case _:
                await self._cmd_default(mto, mtype)
        return

    def _is_command(self, body: str) -> bool:
        return self.prefix_re.match(body) is not None
        

    # ALARM SYSTEM CALLBACK
    def upload_alarm_video(self, data: bytes):
        asyncio.run_coroutine_threadsafe(self._send_file(data), self.loop)

    async def _send_file(self, data: bytes):
        for mto in [self.admin_jid] + self.allowed_jids:
            logger.info(f"Sending alarm video of {len(data)} bytes to {mto}")
            url = await self["xep_0363"].upload_file("alarm.mp4", input_file=data, content_type="video/mp4", timeout=30)
            logger.info(f"{url=}")
            await self._send_encrypted_message(
                mto, "normal", f"Captured video: {url}"
            )


    # COMMANDS
    async def _cmd_default(self, mto: JID, mtype: Optional[MessageTypes]) -> None:
        msg_type = mtype if mtype in ("chat", "normal") else "chat"
        await self._send_encrypted_message(mto, msg_type, "Invalid command! Pease read the /help")

    async def _cmd_help(self, mto: JID, mtype: Optional[MessageTypes]) -> None:
        body = (
            "📖 *Available Commands:*\n\n"
            "🔹 `/take_picture`\n"
            "\tTakes an instant picture and sends it via XMPP (encrypted with OMEMO).\n"
            "🔹 `/record_video <seconds>`\n"
            "\tRecords a video of the specified duration (e.g., `/record_video 10`) and sends it to the user.\n"
            "🔹 `/help`\n"
            "\tDisplays this help message.\n"
            "\n"
            "👮 *Administrator-only Commands:*\n\n"
            "🔸 `/enable_alarm_system`\n"
            "\tEnables the motion detection alarm system.\n"
            "🔸 `/disable_alarm_system`\n"
            "\tDisables the motion detection alarm system.\n"
            "🔸 `/is_alarm_system_enabled`\n"
            "\tReturns if the alarm system is currently enabled.\n"
            "🔸 `/exit`\n"
            "\tSafely shuts down the bot.\n"
            "\n\n\n"
            "All messages and media are securely transmitted using OMEMO encryption 🔐.\n"
        )
        msg_type = mtype if mtype in ("chat", "normal") else "chat"
        return await self._send_encrypted_message(mto, msg_type, body)
    
    async def _cmd_exit(self, mto: JID, mtype: Optional[MessageTypes]) -> None:
        msg_type = mtype if mtype in ("chat", "normal") else "chat"
        await self._send_encrypted_message(mto, msg_type, "Exiting. The system is powering off. 🔌")
        sys.exit(0)

    async def _cmd_take_picture(self, mto: JID, mtype: Optional[MessageTypes]) -> None:
        pass
    
    async def _cmd_record_video(self, mto: JID, mtype: Optional[MessageTypes], args: list) -> None:
        pass
    
    async def _cmd_enable_alarm_system(self, mto: JID, mtype: Optional[MessageTypes]) -> None:
        enable_alarm_system()
        #self.alarm_system.enable()

    async def _cmd_disable_alarm_system(self, mto: JID, mtype: Optional[MessageTypes]) -> None:
        disable_alarm_system()
        # self.alarm_system.disable()

    async def _cmd_is_alarm_system_enabled(self, mto: JID, mtype: Optional[MessageTypes]) -> None:
        msg_type = mtype if mtype in ("chat", "normal") else "chat"
        await self._send_encrypted_message(mto, msg_type, f"Status 🚨 = {is_alarm_system_enabled()}")

