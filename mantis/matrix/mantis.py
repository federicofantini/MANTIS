# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025 Federico Fantini

from ..log import logger
from ..alarm_system import AlarmSystem
from ..main import enable_alarm_system, disable_alarm_system, is_alarm_system_enabled

import os
import re
import sys
import json
import aiofiles # type: ignore
import asyncio
import aiohttp # type: ignore
import traceback
from io import BytesIO
from pathlib import Path
from datetime import datetime
from PIL import Image
from nio import ( # type: ignore
    AsyncClient,
    AsyncClientConfig,
    InviteEvent,
    JoinedRoomsResponse,
    KeyVerificationEvent,
    KeyVerificationStart,
    KeyVerificationMac,
    KeyVerificationKey,
    KeyVerificationCancel,
    LocalProtocolError,
    LoginResponse,
    ProfileSetAvatarError,
    RoomMessageText,
    ToDeviceError,
    ToDeviceMessage,
    UnknownToDeviceEvent,
    UploadResponse,
)
from nio.responses import ProfileGetAvatarResponse # type: ignore
from nio.client.async_client import DataProvider # type: ignore



class Mantis:
    def __init__(self, username: str, password: str, admin_username: str, allowed_usernames: list, alarm_system_enabled: bool):
        self.event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.event_loop)

        self.username = username
        self.password = password
        self.admin_username = admin_username
        self.allowed_usernames = allowed_usernames
        self.alarm_system_enabled = alarm_system_enabled

        self.mantis_home = Path.home() / '.mantis'
        self.mantis_home.mkdir(parents=True, exist_ok=True)
        self.mantis_store = self.mantis_home / 'store'
        self.mantis_store.mkdir(parents=True, exist_ok=True)
        self.mantis_config = self.mantis_home / 'config.json'

    async def loop(self) -> None:
        homeserver = f"https://{self.username.split(':')[1]}"

        # Login to Matrix homeserver in case of first use
        if not os.path.exists(self.mantis_config):
            logger.info("First time use. Did not find credential file. Loggin in.")

            self.client = AsyncClient(
                homeserver, 
                self.username
            )

            resp = await self.client.login(self.password, device_name="mantis-bot")

            # Check that we logged in successfully
            if isinstance(resp, LoginResponse):
                self._write_details_to_disk(resp, homeserver)
            else:
                logger.warning(f"Failed to log in: {resp}")
                sys.exit(1)

        # Restore created or already existed session
        async with aiofiles.open(self.mantis_config) as f:
            contents = await f.read()

        config = json.loads(contents)
        self.client = AsyncClient(
            config["homeserver"],
            user=config["user_id"],
            device_id=config["device_id"],
            store_path=self.mantis_store,
            config=AsyncClientConfig(
                max_limit_exceeded=0,
                max_timeouts=0,
                store_sync_tokens=True,
                encryption_enabled=True,
            ),
            ssl=True,
            proxy=None,
        )
        
        self.client.restore_login(
            user_id=config["user_id"],
            device_id=config["device_id"],
            access_token=config["access_token"],
        )

        # Get my rooms
        joined_rooms = await self.client.joined_rooms()
        if isinstance(joined_rooms, JoinedRoomsResponse):
            self.my_rooms = joined_rooms.rooms
        else:
            logger.warning("Cannot retrieve joined rooms...")
            self.my_rooms = []
        logger.info(f"{self.my_rooms=}")

        # Keys stuff
        if self.client.should_upload_keys:
            await self.client.keys_upload()

        if self.client.should_query_keys:
            await self.client.keys_query()

        if self.client.should_claim_keys:
            await self.client.keys_claim()

        await self.client.sync(full_state=True)

        # Bot aesthetic configuration 
        await self.client.set_displayname("Mantis")
        await self._setAvatar(Path('.') / "image.png")

        # NOTE: The trust process relates to the interlocutor's devices.
        #       On our side, we automatically trust all devices belonging 
        #       to verified users, following a predefined policy.
        for user_id in ([self.admin_username] + self.allowed_usernames):
            for device_id, olm_device in self.client.device_store[user_id].items():
                if olm_device.trust_state.value != 1:
                    self.client.verify_device(olm_device)
                    logger.info(f"Trusting {device_id} from user {user_id}")

        # Send an "I'm alive" message to all allowed users
        for room_id in self.my_rooms:
            await self._send_message(room_id, "Mantis online 🟢")

        # Add a callback that will be executed on device events.
        self.client.add_to_device_callback(self._key_verification_cb, (KeyVerificationEvent, UnknownToDeviceEvent))

        # Add a callback that will be executed on room events.
        self.client.add_event_callback(self._invite_cb, InviteEvent)
        self.client.add_event_callback(self._message_cb, RoomMessageText)

        # Arm the motion detection alarm system
        self.alarm_system = AlarmSystem(self)
        self.alarm_system.start()
        self.alarm_system.add_task("alarm_system", enable_alarm_system=self.alarm_system_enabled)

        # Sync forever
        await self.client.sync_forever(timeout=30000, full_state=True)

    # Writes the required login details to disk so we can log in later without
    def _write_details_to_disk(self, resp: LoginResponse, homeserver: str) -> None:
        with open(self.mantis_config, "w") as f:
            json.dump(
                {
                    "homeserver": homeserver,  # e.g. "https://matrix.example.org"
                    "user_id": resp.user_id,  # e.g. "@user:example.org"
                    "device_id": resp.device_id,  # device ID, 10 uppercase letters
                    "access_token": resp.access_token,  # cryptogr. access token
                },
                f,
            )
    
    # https://github.com/wreald/matrix-nio/tree/5cb8e99965bcb622101b1d6ad6fa86f5a9debb9a
    # NOTE: This feature is used to automate the verification of a session 
    #       (i.e., another device) linked to the **same account**, not to verify devices from other users!
    #
    #       EXAMPLE:
    #           - You already have your mantis@example.net account configured and verified on Element.
    #           - You start the bot on another device (e.g., a Raspberry Pi), creating a new session.
    #           - In Element, go to Settings > Security & Privacy > Manage Sessions, and verify the new session.
    #           - This callback will then be automatically triggered, completing the verification 
    #             and marking the new session as trusted for your account.
    # NOTE: This feature does not allow verifying another user's device via QR code.
    #       There is no callback available for that — it must be done manually!
    #       This mechanism works as a chain of trust: 
    #           you trust your own devices through this callback, 
    #           other users trust you by Out-of-Band (OOB) Verification through QR-code (no emoji!), 
    #           and as a result, they implicitly trust your verified devices.
    async def _key_verification_cb(self, event: KeyVerificationEvent | UnknownToDeviceEvent) -> None:
        """Handle events sent to device."""
        try:
            client = self.client

            if event.source['type'] == 'm.key.verification.request':
                """First step in new flow: receive a request proposing
                a set of verification methods, and in this case respond
                saying we only support SAS verification.
                """
                logger.info(
                    "Got verification request. "
                    "Waiting for other device to accept SAS method..."
                )
                if 'm.sas.v1' not in event.source['content']['methods']:
                    logger.warning(
                        "Other device does not support SAS authentication. "
                        f"Methods: {event.source['content']['methods']}."
                    )
                    return
                assert client.device_id is not None
                assert client.user_id is not None
                txid = event.source['content']['transaction_id']
                ready_event = ToDeviceMessage(
                    type                = 'm.key.verification.ready',
                    recipient           = event.sender,
                    recipient_device    = event.source['content']['from_device'],
                    content             = {
                        'from_device': client.device_id,
                        'methods': ['m.sas.v1'],
                        'transaction_id': txid,
                    },
                )
                resp = await client.to_device(ready_event, txid)
                if isinstance(resp, ToDeviceError):
                    logger.error(f"to_device failed with {resp}")
            elif isinstance(event, KeyVerificationStart):  # first step
                """first step: receive KeyVerificationStart
                KeyVerificationStart(
                    source={'content':
                            {'method': 'm.sas.v1',
                             'from_device': 'DEVICEIDXY',
                             'key_agreement_protocols':
                                ['curve25519-hkdf-sha256', 'curve25519'],
                             'hashes': ['sha256'],
                             'message_authentication_codes':
                                ['hkdf-hmac-sha256', 'hmac-sha256'],
                             'short_authentication_string':
                                ['decimal', 'emoji'],
                             'transaction_id': 'SomeTxId'
                             },
                            'type': 'm.key.verification.start',
                            'sender': '@user2:example.org'
                            },
                    sender='@user2:example.org',
                    transaction_id='SomeTxId',
                    from_device='DEVICEIDXY',
                    method='m.sas.v1',
                    key_agreement_protocols=[
                        'curve25519-hkdf-sha256', 'curve25519'],
                    hashes=['sha256'],
                    message_authentication_codes=[
                        'hkdf-hmac-sha256', 'hmac-sha256'],
                    short_authentication_string=['decimal', 'emoji'])
                """

                if "emoji" not in event.short_authentication_string:
                    logger.error(
                        "Other device does not support emoji verification "
                        f"{event.short_authentication_string}."
                    )
                    return
                resp = await client.accept_key_verification(event.transaction_id)
                if isinstance(resp, ToDeviceError):
                    logger.error(f"accept_key_verification failed with {resp}")

                sas = client.key_verifications[event.transaction_id]

                todevice_msg = sas.share_key()
                resp = await client.to_device(todevice_msg)
                if isinstance(resp, ToDeviceError):
                    logger.error(f"to_device failed with {resp}")

            elif isinstance(event, KeyVerificationCancel):  # anytime
                """at any time: receive KeyVerificationCancel
                KeyVerificationCancel(source={
                    'content': {'code': 'm.mismatched_sas',
                                'reason': 'Mismatched authentication string',
                                'transaction_id': 'SomeTxId'},
                    'type': 'm.key.verification.cancel',
                    'sender': '@user2:example.org'},
                    sender='@user2:example.org',
                    transaction_id='SomeTxId',
                    code='m.mismatched_sas',
                    reason='Mismatched short authentication string')
                """

                # There is no need to issue a
                # client.cancel_key_verification(tx_id, reject=False)
                # here. The SAS flow is already cancelled.
                # We only need to inform the user.
                logger.warning(
                    f"Verification has been cancelled by {event.sender} "
                    f'for reason "{event.reason}".'
                )

            elif isinstance(event, KeyVerificationKey):  # second step
                """Second step is to receive KeyVerificationKey
                KeyVerificationKey(
                    source={'content': {
                            'key': 'SomeCryptoKey',
                            'transaction_id': 'SomeTxId'},
                        'type': 'm.key.verification.key',
                        'sender': '@user2:example.org'
                    },
                    sender='@user2:example.org',
                    transaction_id='SomeTxId',
                    key='SomeCryptoKey')
                """
                sas = client.key_verifications[event.transaction_id]

                logger.info(f"{sas.get_emoji()}")

                yn = input("Do the emojis match? (Y/N) (C for Cancel) ")
                if yn.lower() == "y":
                    logger.info(
                        "Match! The verification for this " "device will be accepted."
                    )
                    resp = await client.confirm_short_auth_string(event.transaction_id)
                    if isinstance(resp, ToDeviceError):
                        logger.error(f"confirm_short_auth_string failed with {resp}")

                    # Extra step in new flow: once we have completed the SAS
                    # verification successfully, send a 'done' to-device event
                    # to the other device to assert that the verification was
                    # successful.
                    done_message = ToDeviceMessage(
                        type                = 'm.key.verification.done',
                        recipient           = event.sender,
                        recipient_device    = sas.other_olm_device.device_id,
                        content             = {
                            'transaction_id': sas.transaction_id,
                        },
                    )
                    resp = await client.to_device(done_message, sas.transaction_id)
                    if isinstance(resp, ToDeviceError):
                        client.log.error(f"'done' failed with {resp}")

                elif yn.lower() == "n":  # no, don't match, reject
                    logger.error(
                        "No match! Device will NOT be verified "
                        "by rejecting verification."
                    )
                    resp = await client.cancel_key_verification(
                        event.transaction_id, reject=True
                    )
                    if isinstance(resp, ToDeviceError):
                        logger.error(f"cancel_key_verification failed with {resp}")
                else:  # C or anything for cancel
                    logger.warning("Cancelled by user! Verification will be " "cancelled.")
                    resp = await client.cancel_key_verification(
                        event.transaction_id, reject=False
                    )
                    if isinstance(resp, ToDeviceError):
                        logger.error(f"cancel_key_verification failed with {resp}")

            elif isinstance(event, KeyVerificationMac):  # third step
                """Third step is to receive KeyVerificationMac
                KeyVerificationMac(
                    source={'content': {
                        'mac': {'ed25519:DEVICEIDXY': 'SomeKey1',
                                'ed25519:SomeKey2': 'SomeKey3'},
                        'keys': 'SomeCryptoKey4',
                        'transaction_id': 'SomeTxId'},
                        'type': 'm.key.verification.mac',
                        'sender': '@user2:example.org'},
                    sender='@user2:example.org',
                    transaction_id='SomeTxId',
                    mac={'ed25519:DEVICEIDXY': 'SomeKey1',
                         'ed25519:SomeKey2': 'SomeKey3'},
                    keys='SomeCryptoKey4')
                """
                sas = client.key_verifications[event.transaction_id]
                try:
                    todevice_msg = sas.get_mac()
                except LocalProtocolError as e:
                    # e.g. it might have been cancelled by ourselves
                    logger.warning(
                        f"Cancelled or protocol error: Reason: {e}.\n"
                        f"Verification with {event.sender} not concluded. "
                        "Try again?"
                    )
                else:
                    resp = await client.to_device(todevice_msg)
                    if isinstance(resp, ToDeviceError):
                        logger.error(f"to_device failed with {resp}")
            elif event.source['type'] == 'm.key.verification.done':
                # Final step, other device acknowledges verification success.
                txid = event.source['content']['transaction_id']
                sas = client.key_verifications[txid]

                logger.info(
                    f"sas.we_started_it = {sas.we_started_it}\n"
                    f"sas.sas_accepted = {sas.sas_accepted}\n"
                    f"sas.canceled = {sas.canceled}\n"
                    f"sas.timed_out = {sas.timed_out}\n"
                    f"sas.verified = {sas.verified}\n"
                    f"sas.verified_devices = {sas.verified_devices}\n"
                )
                logger.info(
                    "Emoji verification was successful!\n"
                    "Hit Control-C to stop the program or "
                    "initiate another Emoji verification from "
                    "another device or room."
                )
            else:
                logger.error(
                    f"Received unexpected event type {type(event)}. "
                    f"Event is {event}. Event will be ignored."
                )
        except Exception:
            logger.error(traceback.format_exc())

    # Join invited rooms (if sender is authorized)
    async def _invite_cb(self, room, event) -> None:
        if room.room_id not in self.my_rooms and event.sender in ([self.admin_username] + self.allowed_usernames):
            await self.client.join(room.room_id)
            self.my_rooms.append(room.room_id)
            logger.info(f'Accepted invite to room {room.room_id} from {event.sender}')

    async def _message_cb(self, room, event) -> None:
        # Check if valid message
        if not hasattr(event, 'body'):
            return

        # Check if the message is E2E encrypted
        if not event.decrypted:
            logger.warning(
                f"Received and unencrypted message from {room.display_name} {room.user_name(event.sender)}: {event.body}"
            )
            return

        room_id = room.room_id
        if self._is_sender_verified(event.sender):
            if self._check_allowed_user(event.sender):

                # Parse commands
                cmd, args = self._parse_command(event.body)
                logger.debug(f"Command \"{cmd}\" with arguments {args} in room {room_id}")
                
                # Dispatch commands
                match cmd:
                    # ALLOWED USERS + ADMIN
                    case "help":
                        await self._cmd_help(room_id)
                    case "take_picture":
                        await self._cmd_take_picture(room_id)
                    case "record_video":
                        await self._cmd_record_video(room_id, int(args[0]) if args else 10) # default 10 seconds
                    # ADMIN
                    case "exit":
                        if self._check_admin(event.sender):
                            await self._cmd_exit(room_id)
                    case "enable_alarm_system":
                        if self._check_admin(event.sender):
                            await self._cmd_enable_alarm_system(room_id)
                    case "disable_alarm_system":
                        if self._check_admin(event.sender):
                            await self._cmd_disable_alarm_system(room_id)
                    case "is_alarm_system_enabled":
                        if self._check_admin(event.sender):
                            await self._cmd_is_alarm_system_enabled(room_id)
                    case _:
                        await self._cmd_default(room_id)

    # Regex parse to (command, arguments)
    def _parse_command(self, message: str) -> tuple[str | None, list[str] | None]:
        match = re.findall(r'^!([\w\d_]*)\s?(.*)$', message)
        if match:
            return (match[0][0], (match[0][1].split()))
        else:
            return (None, None)
    
    # Check if admin user
    def _check_admin(self, username: str) -> bool:
        return username == self.admin_username

    # Check if allowed user = admin + allowed users
    def _check_allowed_user(self, username: str) -> bool:
        return username in ([self.admin_username] + self.allowed_usernames)

    # Check if sender has a trusted device
    def _is_sender_verified(self, sender: str) -> bool:
        devices = [d for d in self.client.device_store.active_user_devices(sender)]
        return all(map(lambda d: d.trust_state.value == 1, devices))

    # Send simple text messages to rooms
    async def _send_message(self, room_id: str, body: str, formatted_body: str = "") -> None:
        if not formatted_body:
            formatted_body = body
        content = {
            'body': body,
            'formatted_body': formatted_body,
            'format': 'org.matrix.custom.html',
            'msgtype': 'm.text'
        }
        await self.client.room_send(room_id, 'm.room.message', content)

    # Workaround to send bytes directly to the client.upload() function
    # ref: https://matrix-nio.readthedocs.io/en/latest/nio.html#nio.AsyncClient.upload
    def _bytes_data_provider(self, data: bytes) -> DataProvider:
        def provider(got_429: int = 0, got_timeouts: int = 0) -> bytes:
            return data
        return provider

    # Upload encrypted image (+ thumbnail) and send
    async def _send_image(self, room_id: str, image_data: bytes, height: int, width: int, image_datetime: datetime) -> None:
        logger.info(f"Uploading image {image_datetime} to room {room_id}.")

        # thumbnail generation
        logger.info(f"Thumbnail 128x128 creation from image of {len(image_data)} bytes.")
        thumbnail = Image.open(BytesIO(image_data))
        thumbnail.thumbnail((128, 128))
        thumbnail_bytes = BytesIO()
        thumbnail.save(thumbnail_bytes, format='PNG')
        thumbnail_data = thumbnail_bytes.getvalue()
        
        logger.info(f"Uploading thumbnail of {len(thumbnail_data)} bytes.")
        resp, thumbnail_decryption_keys = await self.client.upload(
            self._bytes_data_provider(thumbnail_data),
            content_type="image/png",
            filename=f"{image_datetime}-thumbnail.png",
            encrypt=True,
            filesize=len(thumbnail_data),
        )

        if (isinstance(resp, UploadResponse)):
            logger.info(f"Thumbnail successfully uploaded to server. Response: {resp}")
        else:
            logger.error(f"Mantis failed to upload the thumbnail. Response: {resp}")

        thumbnail_url = resp.content_uri

        # uploading image
        resp, image_decryption_keys = await self.client.upload(
            self._bytes_data_provider(image_data),
            content_type="image/png",
            filename=f"{image_datetime}.png",
            encrypt=True,
            filesize=len(image_data),
        )

        if (isinstance(resp, UploadResponse)):
            logger.info(f"Image successfully uploaded to server. Response: {resp}")
        else:
            logger.error(f"Mantis failed to upload the image. Response: {resp}")

        image_url = resp.content_uri

        # https://spec.matrix.org/legacy/client_server/r0.6.0#encrypted-files
        content = {
            "body": f"Image {image_datetime}",
            "file": {
                "url": image_url,
                "mimetype": "image/png",
                "v": image_decryption_keys["v"],
                "key": image_decryption_keys["key"],
                "iv": image_decryption_keys["iv"],
                "hashes": image_decryption_keys["hashes"],
            },
            "info": {
                "mimetype": "image/png",
                "h": height,
                "size": len(image_data),
                "thumbnail_file": {
                    "hashes": thumbnail_decryption_keys["hashes"],
                    "iv": thumbnail_decryption_keys["iv"],
                    "key": thumbnail_decryption_keys["key"],
                    "mimetype": "image/png",
                    "url": thumbnail_url,
                    "v": thumbnail_decryption_keys["v"],
                },
                "thumbnail_info": {
                    "h": height,
                    "mimetype": "image/png",
                    "size": len(thumbnail_data),
                    "w": width,
                },
                "w": width,
            },
            "msgtype": "m.image"
        }

        logger.info(content)

        try:
            await self.client.room_send(
                room_id,
                message_type="m.room.message",
                content=content
            )
            logger.info(f"Sent image to room {room_id}.")
        except Exception:
            logger.info(f"Failed to send image to room {room_id}.")
            logger.info(traceback.format_exc())

    # Upload encrypted video (+ thumbnail) and send
    async def _send_video(self, room_id: str, video_data: bytes, thumbnail_data: bytes, duration: int, height: int, width: int, video_datetime: datetime, is_alarm: bool) -> None:
        logger.info(f"Uploading video {video_datetime} to room {room_id}.")

        # thumbnail generation
        logger.info(f"Thumbnail 128x128 creation from image of {len(thumbnail_data)} bytes.")
        thumbnail = Image.open(BytesIO(thumbnail_data))
        thumbnail.thumbnail((128, 128))
        thumbnail_bytes = BytesIO()
        thumbnail.save(thumbnail_bytes, format='PNG')
        thumbnail_data = thumbnail_bytes.getvalue()
        
        logger.info(f"Uploading thumbnail of {len(thumbnail_data)} bytes.")
        resp, thumbnail_decryption_keys = await self.client.upload(
            self._bytes_data_provider(thumbnail_data),
            content_type="image/png",
            filename=f"{video_datetime}-thumbnail.png",
            encrypt=True,
            filesize=len(thumbnail_data),
        )

        if (isinstance(resp, UploadResponse)):
            logger.info(f"Thumbnail successfully uploaded to server. Response: {resp}")
        else:
            logger.error(f"Mantis failed to upload the thumbnail. Response: {resp}")

        thumbnail_url = resp.content_uri

        # upload video
        logger.info(f"Uploading video of {len(video_data)} bytes.")
        resp, video_decryption_keys = await self.client.upload(
            self._bytes_data_provider(video_data),
            content_type="video/mp4",
            filename=f"{video_datetime}.mp4",
            encrypt=True,
            filesize=len(video_data),
        )
        
        if (isinstance(resp, UploadResponse)):
            logger.info(f"Video successfully uploaded to server. Response: {resp}")
        else:
            logger.error(f"Mantis failed to upload the video. Response: {resp}")

        video_url = resp.content_uri

        # https://spec.matrix.org/legacy/client_server/r0.6.0#encrypted-files
        content = {
            "body": f"ALARM VIDEO {video_datetime}" if is_alarm else f"Recorded video {video_datetime}",
            "file": {
                "url": video_url,
                "mimetype": "video/mp4",
                "v": video_decryption_keys["v"],
                "key": video_decryption_keys["key"],
                "iv": video_decryption_keys["iv"],
                "hashes": video_decryption_keys["hashes"],
            },
            "info": {
                "mimetype": "video/mp4",
                "h": height,
                "size": len(video_data),
                "thumbnail_file": {
                    "hashes": thumbnail_decryption_keys["hashes"],
                    "iv": thumbnail_decryption_keys["iv"],
                    "key": thumbnail_decryption_keys["key"],
                    "mimetype": "image/png",
                    "url": thumbnail_url,
                    "v": thumbnail_decryption_keys["v"],
                },
                "thumbnail_info": {
                    "h": height,
                    "mimetype": "image/png",
                    "size": len(thumbnail_data),
                    "w": width,
                },
                "w": width,
            },
            "msgtype": "m.video"
        }

        try:
            await self.client.room_send(
                room_id,
                message_type="m.room.message",
                content=content
            )
            logger.info(f"Sent video to room {room_id}.")
        except Exception:
            logger.info(f"Failed to send video to room {room_id}.")
            logger.info(traceback.format_exc())

    # ALARM SYSTEM SYNCHRONOUS CALLBACKS
    def upload_video(self, video_data: bytes, thumbnail_data: bytes, duration: int, height: int, width: int, is_alarm: bool) -> None:
        for room_id in self.my_rooms:
            asyncio.run_coroutine_threadsafe(
                self._send_video(
                    room_id,
                    video_data,
                    thumbnail_data,
                    duration,
                    height,
                    width,
                    datetime.now().replace(microsecond=0),
                    is_alarm,
                ), 
                self.event_loop
            )
    
    def upload_image(self, image_data: bytes, height: int, width: int) -> None:
        for room_id in self.my_rooms:
            asyncio.run_coroutine_threadsafe(
                self._send_image(
                    room_id,
                    image_data,
                    height,
                    width,
                    datetime.now().replace(microsecond=0),
                ), 
                self.event_loop
            )

    # COMMANDS
    async def _cmd_default(self, room_id: str) -> None:
        await self._send_message(room_id, "Invalid command! Pease read the !help")

    async def _cmd_help(self, room_id: str) -> None:
        body = (
            """
            <p>📖 <em>Available Commands:</em></p>
            <ul>
            <li><code>!take_picture</code><span> Takes an instant picture and sends it via XMPP (encrypted with OLM).</span></li>
            <li><code>!record_video &lt;seconds&gt;</code><span> Records a video of the specified duration (e.g., `!record_video 10`) and sends it to the user.</span></li>
            <li><code>!help</code><span> Displays this help message.</span></li>
            </ul>
            <p>👮 <em>Administrator-only Commands:</em></p>
            <ul>
            <li><code>!enable_alarm_system</code><span> Enables the motion detection alarm system.</span></li>
            <li><code>!disable_alarm_system</code><span> Disables the motion detection alarm system.</span></li>
            <li><code>!is_alarm_system_enabled</code><span> Returns if the alarm system is currently enabled.</span></li>
            <li><code>!exit</code><span> Safely shuts down the bot.</span></li>
            </ul>
            <p>All messages and media are securely transmitted using OLM encryption 🔐.</p>

            """
        )
        await self._send_message(room_id, body, body)
    
    async def _cmd_exit(self, room_id: str) -> None:
        await self._send_message(room_id, "Exiting. The system is powering off. 🔴")
        self.alarm_system.exit()
        sys.exit(0)

    async def _cmd_take_picture(self, room_id: str) -> None:
        self.alarm_system.add_task("take_picture")
    
    async def _cmd_record_video(self, room_id: str, duration: int) -> None:
        try:
            duration = int(duration)
        except ValueError:
            await self._send_message(room_id, "Invalid duration parameter time.")
        else:
            if duration > 300:
                await self._send_message(room_id, "You have exceeded the maximum number of seconds to take a video: 300.")
            elif duration < 0:
                await self._send_message(room_id, "Invalid duration parameter time.")
            else:
                self.alarm_system.add_task("record_video", record_video_duration=duration)
    
    async def _cmd_enable_alarm_system(self, room_id: str) -> None:
        enable_alarm_system()
        self.alarm_system.add_task("alarm_system", enable_alarm_system=True)

    async def _cmd_disable_alarm_system(self, room_id: str) -> None:
        disable_alarm_system()
        self.alarm_system.add_task("alarm_system", enable_alarm_system=False)

    async def _cmd_is_alarm_system_enabled(self, room_id: str) -> None:
        await self._send_message(room_id, f"Status 🚨 = {is_alarm_system_enabled()}")

    # AVATAR
    async def _setAvatar(self, image_path: Path) -> None:
        response = await self.client.get_avatar()

        if isinstance(response, ProfileGetAvatarResponse):
            avatarUrl = await self.client.mxc_to_http(response.avatar_url)

            async with aiohttp.ClientSession() as session:
                async with session.get(avatarUrl) as response:
                    if response.status == 200:

                        currentAvatarBytes = await response.read()
                        newAvatarBytes = Path(image_path).read_bytes()

                        if currentAvatarBytes == newAvatarBytes:
                            return

        fileStat = image_path.stat()

        with open(str(image_path), "r+b") as f:
            logger.info(f'Seeting avatar for user "{image_path.stem}"')

            response, _ = await self.client.upload(
                f,
                content_type=f"image/{image_path.suffix[1:]}",
                filesize=fileStat.st_size,
            )

            if isinstance(response, UploadResponse):
                response = await self.client.set_avatar(response.content_uri)

                if isinstance(response, ProfileSetAvatarError):
                    logger.error("Failed to set avatar")

            else:
                logger.error(f'Failed to upload file: {image_path}')