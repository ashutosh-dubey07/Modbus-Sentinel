import pytest

from modbus_sentinel.client import ModbusError, read_holding_registers
from modbus_sentinel.config import DeviceConfig


def test_live_device_reads_are_disabled():
    device = DeviceConfig(
        name="Demo PLC",
        host="127.0.0.1",
        port=1502,
        unit_id=1,
        start_address=0,
        register_count=1,
        poll_interval_seconds=2.0,
        timeout_seconds=1.0,
    )

    with pytest.raises(ModbusError, match="simulation-only"):
        read_holding_registers(device)
