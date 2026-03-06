"""CLI principal para analizar tramas Ethernet II desde un archivo de captura."""

from __future__ import annotations

import argparse
import sys

from ethernet_parser import format_frames_table, parse_ethernet_ii_frames


def build_parser() -> argparse.ArgumentParser:
    """Construye el parser de argumentos de línea de comandos."""

    parser = argparse.ArgumentParser(
        description="Analiza tramas Ethernet II en archivos .pcap/.pcapng"
    )
    parser.add_argument(
        "--file",
        required=True,
        help="Ruta al archivo de captura (.pcap o .pcapng)",
    )
    return parser


def main() -> int:
    """Punto de entrada principal del programa."""

    parser = build_parser()
    args = parser.parse_args()

    try:
        frames, skipped = parse_ethernet_ii_frames(args.file)
    except (FileNotFoundError, PermissionError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(format_frames_table(frames))
    if skipped:
        print(f"\nTramas omitidas (no Ethernet II o no Ethernet): {skipped}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
