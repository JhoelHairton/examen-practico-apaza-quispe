#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
visualizar.py  —  Laboratorio 1.3 (Visualización)
Evaluación Práctica Final — Seguridad Informática (Unidad IV)
Autor: Jhoel AQ

Genera 3 gráficas a partir de auth.log y access.log y las guarda como PNG
en la carpeta lab1/graficas/:
  1. top10_ssh.png      — Barras: Top 10 IPs con más intentos SSH fallidos.
  2. timeline_http.png  — Línea: nº de peticiones HTTP por hora.
  3. heatmap_http.png   — Heatmap: peticiones HTTP por hora y código (200/301/404/500).

Reutiliza los parsers de analizar_ssh.py y analizar_web.py.

Uso:
    python visualizar.py
    # (ejecutar desde la raíz del repo  ->  python lab1/visualizar.py
    #  o desde dentro de lab1/          ->  python visualizar.py)
"""

from collections import Counter, defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")          # backend sin ventana (apto para servidores/headless)
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

# Parsers ya implementados en las tareas 1.1 y 1.2
from analizar_ssh import parsear_auth_log, DEFAULT_LOG as LOG_SSH, TOP_N
from analizar_web import parsear_access_log, DEFAULT_LOG as LOG_WEB

BASE_DIR = Path(__file__).resolve().parent
DIR_GRAFICAS = BASE_DIR / "graficas"
DIR_GRAFICAS.mkdir(exist_ok=True)

CODIGOS_INTERES = [200, 301, 404, 500]      # códigos pedidos para el heatmap
sns.set_theme(style="whitegrid")


def grafico_top10_ssh() -> None:
    """Barras horizontales con el Top 10 de IPs por intentos SSH fallidos."""
    intentos = parsear_auth_log(LOG_SSH)
    top = intentos.most_common(TOP_N)
    ips = [ip for ip, _ in top][::-1]          # invertido: la mayor arriba
    valores = [n for _, n in top][::-1]

    plt.figure(figsize=(10, 6))
    barras = plt.barh(ips, valores, color=sns.color_palette("Reds_r", len(ips)))
    plt.bar_label(barras, padding=3, fontsize=9)
    plt.title("Top 10 IPs con más intentos SSH fallidos", fontsize=14, weight="bold")
    plt.xlabel("Número de intentos fallidos")
    plt.ylabel("Dirección IP de origen")
    plt.tight_layout()
    salida = DIR_GRAFICAS / "top10_ssh.png"
    plt.savefig(salida, dpi=120)
    plt.close()
    print(f"[OK] {salida.name}")


def _peticiones_por_hora(registros: list) -> Counter:
    horas = Counter()
    for r in registros:
        if r["dt"] is not None:
            horas[r["dt"].hour] += 1
    return horas


def grafico_timeline_http(registros: list) -> None:
    """Línea de tiempo: nº de peticiones HTTP por hora del día (0-23)."""
    horas = _peticiones_por_hora(registros)
    x = list(range(24))
    y = [horas.get(h, 0) for h in x]

    plt.figure(figsize=(11, 5))
    plt.plot(x, y, marker="o", linewidth=2, color="#1f77b4")
    plt.fill_between(x, y, alpha=0.15, color="#1f77b4")
    plt.title("Peticiones HTTP por hora", fontsize=14, weight="bold")
    plt.xlabel("Hora del día")
    plt.ylabel("Número de peticiones")
    plt.xticks(x)
    plt.tight_layout()
    salida = DIR_GRAFICAS / "timeline_http.png"
    plt.savefig(salida, dpi=120)
    plt.close()
    print(f"[OK] {salida.name}")


def grafico_heatmap_http(registros: list) -> None:
    """Heatmap: peticiones HTTP por hora (cols) y código de respuesta (filas)."""
    # matriz[codigo][hora] = conteo
    matriz = defaultdict(lambda: np.zeros(24, dtype=int))
    for r in registros:
        if r["dt"] is not None and r["status"] in CODIGOS_INTERES:
            matriz[r["status"]][r["dt"].hour] += 1

    datos = np.array([matriz[c] for c in CODIGOS_INTERES])

    plt.figure(figsize=(13, 4.5))
    sns.heatmap(
        datos,
        annot=True, fmt="d", cmap="YlOrRd",
        xticklabels=list(range(24)),
        yticklabels=[str(c) for c in CODIGOS_INTERES],
        cbar_kws={"label": "Nº de peticiones"},
        linewidths=0.5, linecolor="white",
    )
    plt.title("Peticiones HTTP por hora y código de respuesta",
              fontsize=14, weight="bold")
    plt.xlabel("Hora del día")
    plt.ylabel("Código HTTP")
    plt.tight_layout()
    salida = DIR_GRAFICAS / "heatmap_http.png"
    plt.savefig(salida, dpi=120)
    plt.close()
    print(f"[OK] {salida.name}")


def main() -> None:
    print("[*] Generando gráficas en lab1/graficas/ ...")
    grafico_top10_ssh()

    registros_web = parsear_access_log(LOG_WEB)
    grafico_timeline_http(registros_web)
    grafico_heatmap_http(registros_web)

    print("[OK] Las 3 gráficas fueron generadas correctamente.")


if __name__ == "__main__":
    main()
