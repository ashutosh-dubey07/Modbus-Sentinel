"""Parser for the Modbus TCP request subset used by local scenarios."""

from __future__ import annotations

from dataclasses import dataclass
import struct


class ModbusFrameError(ValueError):
    """Raised when a byte sequence is not a supported, valid request."""


@dataclass(frozen=True)
class ParsedRequest:
    transaction_id: int
    unit_id: int
    function_code: int
    start_address: int
    quantity: int | None = None
    register_value: int | None = None


def parse_modbus_tcp_request(frame: bytes) -> ParsedRequest:
    """Parse one complete Modbus TCP request for function codes 3, 4, or 6."""
    if not isinstance(frame, (bytes, bytearray, memoryview)):
        raise ModbusFrameError("frame must be bytes")
    frame = bytes(frame)
    if len(frame) < 8:
        raise ModbusFrameError("frame is shorter than a Modbus TCP header and function code")

    transaction_id, protocol_id, length, unit_id = struct.unpack(">HHHB", frame[:7])
    if protocol_id != 0:
        raise ModbusFrameError("protocol ID must be 0")
    if not 2 <= length <= 254:
        raise ModbusFrameError("MBAP length must be from 2 to 254")
    if len(frame) != 6 + length:
        raise ModbusFrameError(
            f"MBAP length says {6 + length} bytes, received {len(frame)}"
        )

    pdu = frame[7:]
    function_code = pdu[0]
    if function_code in {3, 4}:
        if len(pdu) != 5:
            raise ModbusFrameError("read request must contain a function, address, and quantity")
        start_address, quantity = struct.unpack(">HH", pdu[1:])
        if not 1 <= quantity <= 125:
            raise ModbusFrameError("read quantity must be from 1 to 125")
        if start_address + quantity > 65536:
            raise ModbusFrameError("read address range must end at 65535 or below")
        return ParsedRequest(
            transaction_id=transaction_id,
            unit_id=unit_id,
            function_code=function_code,
            start_address=start_address,
            quantity=quantity,
        )

    if function_code == 6:
        if len(pdu) != 5:
            raise ModbusFrameError("write single register request must contain 5 PDU bytes")
        address, value = struct.unpack(">HH", pdu[1:])
        return ParsedRequest(
            transaction_id=transaction_id,
            unit_id=unit_id,
            function_code=function_code,
            start_address=address,
            register_value=value,
        )

    raise ModbusFrameError(f"unsupported function code {function_code}")
