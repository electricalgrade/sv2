# test_bridge.py

import asyncio
from bridge import Bridge, Submit, SubmitShareWithChannelId, SubmitSharesExtended


async def test_submit_translation():
    # Queues to simulate downstream/upstream communication
    rx_downstream = asyncio.Queue()
    tx_upstream = asyncio.Queue()

    bridge = Bridge(rx_downstream, tx_upstream)

    # Run the handler in background
    task = asyncio.create_task(bridge.handle_downstream_messages())

    submit = Submit(
        user_name="miner1",
        job_id="42",
        extra_nonce2=b'\x01\x02\x03\x04',
        time=1234567890,
        nonce=999,
        version_bits=0x10000000
    )
    submit_msg = SubmitShareWithChannelId(
        channel_id=1,
        share=submit,
        version_rolling_mask=0x1fffffff
    )

    # Send to bridge
    await rx_downstream.put(submit_msg)

    # Wait for output
    result: SubmitSharesExtended = await tx_upstream.get()

    assert result.channel_id == 1
    assert result.job_id == 42
    assert result.extranonce == b'\x01\x02\x03\x04'
    assert result.version == (0x20000000 & ~0x1fffffff) | (0x10000000 & 0x1fffffff)
    print("✅ Test passed!")


if __name__ == "__main__":
    asyncio.run(test_submit_translation())

