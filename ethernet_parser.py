"""Lógica de parsing para tramas Ethernet II."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from scapy.all import Ether, rdpcap
from scapy.error import Scapy_Exception

ETHERTYPE_MAP = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
}


@dataclass
class EthernetFrameInfo:
    """Información resumida de una trama Ethernet II."""

    index: int
    mac_destino: str
    mac_origen: str
    ethertype: str
    protocolo: str


def _ethertype_to_name(ethertype: int) -> str:
    return ETHERTYPE_MAP.get(ethertype, "Desconocido")


def parse_ethernet_ii_frames(file_path: str) -> tuple[list[EthernetFrameInfo], int]:
    """Parsea un archivo pcap/pcapng y extrae tramas Ethernet II.

    Returns:
        Una tupla con (tramas_ethernet_ii, cantidad_omitidas).
    """

    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"El archivo no existe: {file_path}")
    if not path.is_file():
        raise ValueError(f"La ruta no es un archivo válido: {file_path}")

    try:
        packets = rdpcap(str(path))
    except PermissionError as exc:
        raise PermissionError(f"Sin permisos para leer el archivo: {file_path}") from exc
    except Scapy_Exception as exc:
        raise ValueError(f"Formato de captura no válido o no soportado: {file_path}") from exc
    except OSError as exc:
        raise ValueError(f"No se pudo leer el archivo de captura: {file_path}") from exc

    frames: list[EthernetFrameInfo] = []
    skipped = 0

    for idx, packet in enumerate(packets, start=1):
        if not packet.haslayer(Ether):
            skipped += 1
            continue

        ether_layer = packet[Ether]
        ethertype_num = int(ether_layer.type)

        # Ethernet II usa EtherType > 1500 (0x05DC).
        if ethertype_num <= 0x05DC:
            skipped += 1
            continue

        frames.append(
            EthernetFrameInfo(
                index=len(frames) + 1,
                mac_destino=str(ether_layer.dst).lower(),
                mac_origen=str(ether_layer.src).lower(),
                ethertype=f"0x{ethertype_num:04X}",
                protocolo=_ethertype_to_name(ethertype_num),
            )
        )

    return frames, skipped


def format_frames_table(frames: Iterable[EthernetFrameInfo]) -> str:
    """Construye una tabla simple en texto para imprimir en consola."""

    rows = list(frames)
    if not rows:
        return "No se encontraron tramas Ethernet II en la captura."

    header = (
        f"{'#':<4} {'MAC Destino':<20} {'MAC Origen':<20} "
        f"{'EtherType':<10} {'Protocolo':<12}"
    )
    separator = "-" * len(header)

    data_lines = [
        f"{row.index:<4} {row.mac_destino:<20} {row.mac_origen:<20} {row.ethertype:<10} {row.protocolo:<12}"
        for row in rows
    ]
    return "\n".join([header, separator, *data_lines])
