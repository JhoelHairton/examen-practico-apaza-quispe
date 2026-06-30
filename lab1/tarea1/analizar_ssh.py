#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analizar_ssh.py  —  Laboratorio 1.1 (Análisis Forense de Logs SSH)
Evaluación Práctica Final — Seguridad Informática (Unidad IV)
Autor: Jhoel AQ

Analiza un log de autenticación SSH (auth.log):
  1. Detecta los intentos de autenticación fallidos ("Failed password").
  2. Extrae y cuenta los intentos por dirección IP de origen.
  3. Imprime un ranking ordenado con las 10 IPs más activas.
  4. Lanza una alerta en consola para cada IP que supere 50 intentos fallidos.
  5. Exporta el resultado a reporte_ssh.json.

Uso:
    python analizar_ssh.py [ruta_auth_log]
    # Por defecto lee  lab1/auth.log  (relativo a la ubicación del script),
    # por lo que funciona tanto con  `python lab1/analizar_ssh.py`
    # como con  `python analizar_ssh.py`  ejecutado dentro de lab1/.
"""

import json
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

# --- Configuración ----------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent           # carpeta lab1/
DEFAULT_LOG = BASE_DIR / "auth.log"
OUTPUT_JSON = BASE_DIR / "reporte_ssh.json"
UMBRAL_ALERTA = 50          # nº de intentos para considerar fuerza bruta (> 50)
TOP_N = 10                  # tamaño del ranking

# Captura la IP de origen en líneas como:
#   Failed password for root from 10.0.128.239 port 24501 ssh2
#   Failed password for invalid user ftp from 193.32.162.55 port 2359 ssh2
PATRON_FALLO = re.compile(
    r"Failed password for (?:invalid user )?\S+ from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def parsear_auth_log(ruta_log: Path) -> Counter:
    """Recorre el log y devuelve un Counter {ip: nº_intentos_fallidos}."""
    intentos = Counter()
    with ruta_log.open("r", encoding="utf-8", errors="ignore") as fh:
        for linea in fh:
            if "Failed password" not in linea:
                continue
            m = PATRON_FALLO.search(linea)
            if m:
                intentos[m.group("ip")] += 1
    return intentos


def imprimir_ranking(intentos: Counter) -> None:
    """Imprime el Top N de IPs ordenado por nº de intentos fallidos."""
    print("=" * 64)
    print(f"  TOP {TOP_N} IPs CON MÁS INTENTOS DE AUTENTICACIÓN SSH FALLIDOS")
    print("=" * 64)
    print(f"  {'#':>2}  {'Dirección IP':<18}{'Intentos':>10}")
    print("-" * 64)
    for pos, (ip, n) in enumerate(intentos.most_common(TOP_N), start=1):
        marca = "   <-- supera umbral" if n > UMBRAL_ALERTA else ""
        print(f"  {pos:>2}  {ip:<18}{n:>10}{marca}")
    print("=" * 64)


def emitir_alertas(intentos: Counter) -> list:
    """Imprime las alertas de fuerza bruta y arma la lista de IPs sospechosas.

    Se consideran 'sospechosas' las IPs del Top N; cada una lleva el flag
    `alerta = True` si supera el umbral de intentos fallidos.
    """
    print("\n--- ANÁLISIS DE AMENAZAS (umbral: > "
          f"{UMBRAL_ALERTA} intentos) ---")
    hay_alerta = False
    for ip, n in intentos.most_common():
        if n > UMBRAL_ALERTA:
            hay_alerta = True
            print(f"[ALERTA] IP: {ip} — {n} intentos fallidos — "
                  f"Posible ataque de fuerza bruta")
    if not hay_alerta:
        print("  (ninguna IP supera el umbral configurado)")

    sospechosas = [
        {"ip": ip, "intentos": n, "alerta": n > UMBRAL_ALERTA}
        for ip, n in intentos.most_common(TOP_N)
    ]
    return sospechosas


def exportar_json(intentos: Counter, sospechosas: list) -> dict:
    reporte = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_intentos_fallidos": sum(intentos.values()),
        "ips_unicas": len(intentos),
        "ips_sospechosas": sospechosas,
    }
    OUTPUT_JSON.write_text(
        json.dumps(reporte, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"\n[OK] Reporte exportado a: {OUTPUT_JSON.name}")
    return reporte


def main() -> None:
    ruta_log = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_LOG
    if not ruta_log.exists():
        sys.exit(f"[ERROR] No se encontró el log: {ruta_log}")

    print(f"[*] Analizando log de autenticación SSH: {ruta_log}")
    intentos = parsear_auth_log(ruta_log)

    if not intentos:
        print("[!] No se encontraron intentos fallidos en el log.")
        return

    print(f"[*] Intentos fallidos totales: {sum(intentos.values())} "
          f"desde {len(intentos)} IPs únicas.\n")
    imprimir_ranking(intentos)
    sospechosas = emitir_alertas(intentos)
    exportar_json(intentos, sospechosas)


if __name__ == "__main__":
    main()
