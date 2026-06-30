#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analizar_web.py  —  Laboratorio 1.2 (Análisis Forense de Logs Web)
Evaluación Práctica Final — Seguridad Informática (Unidad IV)
Autor: Jhoel AQ

Parsea un access.log de Apache en Combined Log Format y detecta:
  1. Escaneo de directorios: más de 20 rutas distintas en menos de 60 s
     desde la misma IP (ventana deslizante).
  2. Peticiones con códigos de respuesta 4xx y 5xx, agrupadas por IP.
  3. Posibles intentos de SQL Injection en la URL: UNION, SELECT, --,
     OR 1=1, ' (comilla simple).
Exporta los hallazgos a reporte_web.json.

Uso:
    python analizar_web.py [ruta_access_log]
    # Por defecto lee  lab1/access.log  (relativo a la ubicación del script).
"""

import json
import re
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote

# --- Configuración ----------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent           # carpeta lab1/
DEFAULT_LOG = BASE_DIR / "access.log"
OUTPUT_JSON = BASE_DIR / "reporte_web.json"

VENTANA_SEG = 60            # ventana temporal para el escaneo de directorios
UMBRAL_PETICIONES = 20     # > 20 peticiones (a rutas distintas) dentro de la ventana

# Combined Log Format de Apache:
# 45.33.32.156 - - [14/Jun/2024:03:13:44 +0000] "GET /x HTTP/1.1" 404 1097 "-" "UA"
PATRON_ACCESO = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<fecha>[^\]]+)\] '
    r'"(?P<metodo>\S+) (?P<url>\S+) (?P<proto>[^"]*)" '
    r'(?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)
FORMATO_FECHA = "%d/%b/%Y:%H:%M:%S %z"

# Firmas de SQL Injection (se buscan sobre la URL decodificada y en minúsculas).
PATRONES_SQLI = ["union", "select", "--", "or 1=1", "'"]


def parsear_access_log(ruta_log: Path) -> list:
    """Devuelve una lista de dicts con los campos de cada petición válida."""
    registros = []
    with ruta_log.open("r", encoding="utf-8", errors="ignore") as fh:
        for linea in fh:
            m = PATRON_ACCESO.search(linea)
            if not m:
                continue
            d = m.groupdict()
            try:
                d["dt"] = datetime.strptime(d["fecha"], FORMATO_FECHA)
            except ValueError:
                d["dt"] = None
            d["status"] = int(d["status"])
            registros.append(d)
    return registros


def detectar_escaneo(registros: list) -> list:
    """Detecta IPs con > UMBRAL_PETICIONES peticiones (a rutas distintas) en < 60 s.

    Para cada IP se ordenan sus peticiones por tiempo y se desliza una ventana
    de 60 s. Si en algún momento la ventana acumula más de 20 peticiones, la IP
    se marca como escáner de directorios; además se reporta cuántas rutas
    DISTINTAS había en ese pico (para evidenciar que es escaneo y no un refresco
    repetido de la misma página).
    """
    por_ip = defaultdict(list)
    for r in registros:
        if r["dt"] is not None:
            por_ip[r["ip"]].append((r["dt"], r["url"]))

    hallazgos = []
    for ip, eventos in por_ip.items():
        eventos.sort(key=lambda e: e[0])
        ventana = deque()                 # tuplas (dt, url) dentro de la ventana
        rutas_ventana = Counter()         # nº de veces que cada url está en ventana
        max_peticiones = 0                # pico de peticiones en una ventana de 60 s
        rutas_en_pico = 0                 # rutas distintas en ese pico
        for dt, url in eventos:
            ventana.append((dt, url))
            rutas_ventana[url] += 1
            # Expulsa por la izquierda lo que quede fuera de la ventana de 60 s.
            while (dt - ventana[0][0]).total_seconds() > VENTANA_SEG:
                _, vieja_url = ventana.popleft()
                rutas_ventana[vieja_url] -= 1
                if rutas_ventana[vieja_url] == 0:
                    del rutas_ventana[vieja_url]
            if len(ventana) > max_peticiones:
                max_peticiones = len(ventana)
                rutas_en_pico = len(rutas_ventana)

        if max_peticiones > UMBRAL_PETICIONES:
            hallazgos.append({
                "ip": ip,
                "peticiones_max_60s": max_peticiones,
                "rutas_distintas_en_pico": rutas_en_pico,
                "rutas_distintas_totales": len({u for _, u in eventos}),
                "total_peticiones": len(eventos),
                "alerta": True,
            })
    hallazgos.sort(key=lambda h: h["peticiones_max_60s"], reverse=True)
    return hallazgos


def agrupar_errores(registros: list) -> list:
    """Agrupa por IP las respuestas con código 4xx y 5xx."""
    por_ip = defaultdict(lambda: {"4xx": 0, "5xx": 0, "codigos": Counter()})
    for r in registros:
        s = r["status"]
        if 400 <= s < 600:
            grupo = "4xx" if s < 500 else "5xx"
            por_ip[r["ip"]][grupo] += 1
            por_ip[r["ip"]]["codigos"][str(s)] += 1

    resultado = []
    for ip, datos in por_ip.items():
        total = datos["4xx"] + datos["5xx"]
        resultado.append({
            "ip": ip,
            "total_errores": total,
            "4xx": datos["4xx"],
            "5xx": datos["5xx"],
            "codigos": dict(datos["codigos"]),
        })
    resultado.sort(key=lambda x: x["total_errores"], reverse=True)
    return resultado


def detectar_sqli(registros: list) -> list:
    """Busca firmas de SQL Injection en la URL (decodificada)."""
    hallazgos = []
    for r in registros:
        # Decodifica %XX y '+' para descubrir payloads ofuscados.
        url_decod = unquote(r["url"]).replace("+", " ").lower()
        coincidencias = [p for p in PATRONES_SQLI if p in url_decod]
        if coincidencias:
            hallazgos.append({
                "ip": r["ip"],
                "metodo": r["metodo"],
                "url": r["url"],
                "status": r["status"],
                "patrones_detectados": coincidencias,
                "timestamp": r["dt"].strftime("%Y-%m-%d %H:%M:%S") if r["dt"] else None,
            })
    return hallazgos


def main() -> None:
    ruta_log = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_LOG
    if not ruta_log.exists():
        sys.exit(f"[ERROR] No se encontró el log: {ruta_log}")

    print(f"[*] Analizando access.log: {ruta_log}")
    registros = parsear_access_log(ruta_log)
    print(f"[*] Peticiones parseadas: {len(registros)}\n")

    # 1) Escaneo de directorios
    escaneo = detectar_escaneo(registros)
    print("--- ESCANEO DE DIRECTORIOS (> 20 peticiones a rutas distintas en < 60 s) ---")
    if escaneo:
        for h in escaneo:
            print(f"[ALERTA] IP: {h['ip']} — {h['peticiones_max_60s']} peticiones "
                  f"({h['rutas_distintas_en_pico']} rutas distintas) en 60 s — "
                  f"Posible escaneo de directorios")
    else:
        print("  (sin escaneos detectados)")

    # 2) SQL Injection
    sqli = detectar_sqli(registros)
    print("\n--- POSIBLES INTENTOS DE SQL INJECTION ---")
    if sqli:
        for h in sqli[:15]:
            print(f"[ALERTA] SQLi desde {h['ip']} {h['metodo']} {h['url']} "
                  f"(status {h['status']}) patrones={h['patrones_detectados']}")
        if len(sqli) > 15:
            print(f"  ... y {len(sqli) - 15} coincidencias más "
                  f"(ver reporte_web.json)")
    else:
        print("  (sin patrones de SQLi detectados)")

    # 3) Errores 4xx/5xx
    errores = agrupar_errores(registros)
    print(f"\n--- ERRORES 4xx/5xx: {len(errores)} IPs con errores "
          f"(Top 5) ---")
    for e in errores[:5]:
        print(f"  {e['ip']:<18} total={e['total_errores']:>4} "
              f"(4xx={e['4xx']}, 5xx={e['5xx']})")

    # Exportar JSON
    reporte = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_peticiones": len(registros),
        "resumen": {
            "ips_escaneo_directorios": len(escaneo),
            "intentos_sqli": len(sqli),
            "ips_con_errores_4xx_5xx": len(errores),
        },
        "escaneo_directorios": escaneo,
        "sql_injection": sqli,
        "errores_4xx_5xx_por_ip": errores,
    }
    OUTPUT_JSON.write_text(
        json.dumps(reporte, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"\n[OK] Reporte exportado a: {OUTPUT_JSON.name}")


if __name__ == "__main__":
    main()
