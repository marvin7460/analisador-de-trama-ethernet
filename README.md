# analizador-de-trama-ethernet

Primera parte de un sniffer académico para analizar campos de tramas **Ethernet II** a partir de una captura de Wireshark (`.pcap` o `.pcapng`).

## Elección de librería

Se usa **Scapy** porque permite leer archivos de captura de forma directa en Python (`rdpcap`) y acceder de manera clara a los campos de la capa Ethernet.

## Estructura del proyecto

- `main.py`: CLI principal.
- `ethernet_parser.py`: parsing y formateo de salida.
- `requirements.txt`: dependencias para entorno virtual.
- `tests/test_ethernet_parser.py`: pruebas unitarias básicas.
- `examples/salida.txt`: ejemplo de salida esperada.

## Instalación (venv)

1. Crear entorno virtual:

   ```bash
   python -m venv .venv
   ```

2. Activar entorno virtual:

   - Linux/macOS:

     ```bash
     source .venv/bin/activate
     ```

   - Windows (PowerShell):

     ```powershell
     .venv\Scripts\Activate.ps1
     ```

3. Instalar dependencias:

   ```bash
   pip install -r requirements.txt
   ```

## Ejecución

```bash
python main.py --file captura.pcapng
```

También funciona con `.pcap`.

## Qué muestra el programa

Para cada trama Ethernet II encontrada:

- MAC destino
- MAC origen
- EtherType (hexadecimal)
- Nombre protocolar (cuando se reconoce: IPv4, ARP, IPv6)

Además, informa cuántas tramas fueron omitidas por no ser Ethernet II.

## Manejo de errores

El programa contempla errores comunes y muestra mensajes claros en consola para casos como:

- archivo inexistente,
- falta de permisos,
- archivo de captura inválido o no soportado.

## Pruebas

```bash
python -m unittest -v
```
