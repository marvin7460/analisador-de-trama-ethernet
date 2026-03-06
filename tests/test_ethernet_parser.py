"""Pruebas unitarias para el parser de Ethernet II."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scapy.all import Dot3, Ether, Raw, wrpcap

from ethernet_parser import EthernetFrameInfo, format_frames_table, parse_ethernet_ii_frames


class EthernetParserTests(unittest.TestCase):
    def test_parse_ethernet_ii_and_skip_dot3(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_path = Path(tmpdir) / "captura.pcap"
            packets = [
                Ether(dst="aa:bb:cc:dd:ee:ff", src="11:22:33:44:55:66", type=0x0800) / Raw(load=b"x"),
                Dot3(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55", len=100) / Raw(load=b"y"),
            ]
            wrpcap(str(pcap_path), packets)

            frames, skipped = parse_ethernet_ii_frames(str(pcap_path))

        self.assertEqual(len(frames), 1)
        self.assertEqual(skipped, 1)
        self.assertEqual(frames[0].mac_destino, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(frames[0].mac_origen, "11:22:33:44:55:66")
        self.assertEqual(frames[0].ethertype, "0x0800")
        self.assertEqual(frames[0].protocolo, "IPv4")

    def test_format_empty_table_message(self) -> None:
        self.assertIn("No se encontraron", format_frames_table([]))

    def test_format_table_with_data(self) -> None:
        frame = EthernetFrameInfo(
            index=1,
            mac_destino="aa:bb:cc:dd:ee:ff",
            mac_origen="11:22:33:44:55:66",
            ethertype="0x0800",
            protocolo="IPv4",
        )

        table = format_frames_table([frame])

        self.assertIn("MAC Destino", table)
        self.assertIn("aa:bb:cc:dd:ee:ff", table)
        self.assertIn("11:22:33:44:55:66", table)
        self.assertIn("0x0800", table)
        self.assertIn("IPv4", table)


if __name__ == "__main__":
    unittest.main()
