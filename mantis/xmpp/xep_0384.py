from ..log import logger

import json
from pathlib import Path
from typing import Any, Dict, FrozenSet, Optional

from omemo.storage import Just, Maybe, Nothing, Storage
from omemo.types import DeviceInformation, JSONType
from slixmpp.plugins import register_plugin  # type: ignore[attr-defined]
from slixmpp_omemo import XEP_0384, TrustLevel



class StorageImpl(Storage):
    def __init__(self) -> None:
        super().__init__()

        mantis_home = Path.home() / '.mantis'
        mantis_home.mkdir(parents=True, exist_ok=True)

        self.JSON_FILE = mantis_home / 'mantis.json'

        self.__data: Dict[str, JSONType] = {}
        try:
            with open(self.JSON_FILE, encoding="utf8") as f:
                self.__data = json.load(f)
        except Exception:
            pass

    async def _load(self, key: str) -> Maybe[JSONType]:
        if key in self.__data:
            return Just(self.__data[key])
        return Nothing()

    async def _store(self, key: str, value: JSONType) -> None:
        self.__data[key] = value
        with open(self.JSON_FILE, "w", encoding="utf8") as f:
            json.dump(self.__data, f)

    async def _delete(self, key: str) -> None:
        self.__data.pop(key, None)
        with open(self.JSON_FILE, "w", encoding="utf8") as f:
            json.dump(self.__data, f)


class XEP_0384Impl(XEP_0384):  # pylint: disable=invalid-name
    def __init__(self, *args: Any, **kwargs: Any) -> None:  # pylint: disable=redefined-outer-name
        super().__init__(*args, **kwargs)

        # Just the type definition here
        self.__storage: Storage

    def plugin_init(self) -> None:
        self.__storage = StorageImpl()

        super().plugin_init()

    @property
    def storage(self) -> Storage:
        return self.__storage

    @property
    def _btbv_enabled(self) -> bool:
        return False

    async def _devices_blindly_trusted(
        self, blindly_trusted: FrozenSet[DeviceInformation], identifier: Optional[str]
    ) -> None:
        logger.info(f"[{identifier}] Devices trusted blindly: {blindly_trusted}")

    async def _prompt_manual_trust(
        self, manually_trusted: FrozenSet[DeviceInformation], identifier: Optional[str]
    ) -> None:
        session_mananger = await self.get_session_manager()

        # Force _devices_blindly_trusted -> I'm a bot not a human :)
        for device in manually_trusted:
            logger.info(f"[{identifier}] Devices trusted blindly: {device}")
            await session_mananger.set_trust(
                device.bare_jid,
                device.identity_key,
                TrustLevel.TRUSTED.value,
            )


register_plugin(XEP_0384Impl)