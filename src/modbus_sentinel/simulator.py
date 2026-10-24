"""A tiny local Modbus TCP server for development and demos."""

from __future__ import annotations

import argparse
import socketserver
import struct


def _recv_exact(connection, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        block = connection.recv(size - len(chunks))
        if not block:
            raise ConnectionError("client closed the connection")
        chunks.extend(block)
    return bytes(chunks)


class _ModbusHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        connection = self.request
        try:
            header = _recv_exact(connection, 7)
            transaction_id, protocol_id, length, unit_id = struct.unpack(">HHHB", header)
            if protocol_id != 0 or length < 2 or length > 254:
                return

            pdu = _recv_exact(connection, length - 1)
            function = pdu[0]
            if function != 3:
                response_pdu = bytes((function | 0x80, 1))
            elif len(pdu) != 5:
                response_pdu = bytes((function | 0x80, 3))
            else:
                start_address, quantity = struct.unpack(">HH", pdu[1:])
                if quantity < 1 or quantity > 125 or start_address + quantity > 65536:
                    response_pdu = bytes((function | 0x80, 3))
                else:
                    # Stable sample readings that sit within config.toml's limits.
                    values = [425 if address == 0 else 178 if address == 1 else 100 + address
                              for address in range(start_address, start_address + quantity)]
                    payload = struct.pack(f">{quantity}H", *values)
                    response_pdu = bytes((function, len(payload))) + payload

            response_header = struct.pack(
                ">HHHB", transaction_id, 0, len(response_pdu) + 1, unit_id
            )
            connection.sendall(response_header + response_pdu)
        except (ConnectionError, OSError, struct.error):
            return


class _ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local Modbus TCP demo device")
    parser.add_argument("--host", default="127.0.0.1", help="interface to listen on")
    parser.add_argument("--port", type=int, default=1502, help="TCP port (default: 1502)")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be from 1 to 65535")

    try:
        with _ThreadedServer((args.host, args.port), _ModbusHandler) as server:
            print(f"Demo Modbus TCP device listening at {args.host}:{args.port}. Press Ctrl+C to stop.")
            server.serve_forever()
    except KeyboardInterrupt:
        print("Demo simulator stopped.")
    except OSError as exc:
        print(f"Could not start simulator: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
