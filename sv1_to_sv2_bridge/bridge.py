# bridge.py

import asyncio
from dataclasses import dataclass
from typing import Optional


@dataclass
class Submit:
    user_name: str
    job_id: str
    extra_nonce2: bytes
    time: int
    nonce: int
    version_bits: Optional[int] = None


@dataclass
class SubmitShareWithChannelId:
    channel_id: int
    share: Submit
    version_rolling_mask: Optional[int]


@dataclass
class SubmitSharesExtended:
    channel_id: int
    sequence_number: int
    job_id: int
    nonce: int
    ntime: int
    version: int
    extranonce: bytes


class Bridge:
    def __init__(self, rx_downstream: asyncio.Queue, tx_upstream: asyncio.Queue):
        self.rx_downstream = rx_downstream
        self.tx_upstream = tx_upstream
        self.default_version = 0x20000000  # Sample default version

    async def handle_downstream_messages(self):
        while True:
            msg = await self.rx_downstream.get()
            if isinstance(msg, SubmitShareWithChannelId):
                translated = self.translate_submit(msg)
                await self.tx_upstream.put(translated)

    def translate_submit(self, share_msg: SubmitShareWithChannelId) -> SubmitSharesExtended:
        submit = share_msg.share
        version = self.default_version

        if share_msg.version_rolling_mask is not None and submit.version_bits is not None:
            mask = share_msg.version_rolling_mask
            vb = submit.version_bits
            version = (self.default_version & ~mask) | (vb & mask)

        return SubmitSharesExtended(
            channel_id=share_msg.channel_id,
            sequence_number=0,
            job_id=int(submit.job_id),
            nonce=submit.nonce,
            ntime=submit.time,
            version=version,
            extranonce=submit.extra_nonce2,
        )

