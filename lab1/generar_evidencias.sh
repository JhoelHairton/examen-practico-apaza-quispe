#!/bin/bash
# =============================================================================
# generar_evidencias.sh  —  Ayuda a capturar las evidencias del Laboratorio 1
# Evaluación Práctica Final — Seguridad Informática (Unidad IV)
#
# Pone tu NOMBRE en la barra de título de la terminal e imprime un banner con
# nombre + fecha/hora antes de cada salida, para que cada screenshot cumpla los
# requisitos del examen. Toma la captura DESPUÉS de que aparezca la salida.
#
# Uso:
#   bash generar_evidencias.sh 1.1a   # ejecución de analizar_ssh.py  (SCR-1.1a)
#   bash generar_evidencias.sh 1.1b   # contenido de reporte_ssh.json (SCR-1.1b)
#   bash generar_evidencias.sh 1.2a   # ejecución de analizar_web.py  (SCR-1.2a)
#   bash generar_evidencias.sh 1.2b   # contenido de reporte_web.json (SCR-1.2b)
# =============================================================================

NOMBRE="Jhoel Apaza Quispe"
cd "$(dirname "$0")" || exit 1

# Nombre en la BARRA DE TÍTULO de la terminal (requisito del examen)
printf '\033]0;%s — Examen Seguridad Informatica\007' "$NOMBRE"

banner () {
  echo "=================================================================="
  echo "  Estudiante : $NOMBRE"
  echo "  Fecha/hora : $(date '+%Y-%m-%d %H:%M:%S')"
  echo "  Evidencia  : $1"
  echo "=================================================================="
}

# python3 en Linux; usa 'python' si tu sistema lo llama así
PY=python3; command -v $PY >/dev/null 2>&1 || PY=python

case "$1" in
  1.1a) banner "SCR-1.1a — ejecucion analizar_ssh.py"; echo; $PY analizar_ssh.py ;;
  1.1b) banner "SCR-1.1b — contenido reporte_ssh.json"; echo; cat reporte_ssh.json ;;
  1.2a) banner "SCR-1.2a — ejecucion analizar_web.py"; echo; $PY analizar_web.py ;;
  1.2b) banner "SCR-1.2b — contenido reporte_web.json"; echo; cat reporte_web.json ;;
  *)    echo "Uso: bash generar_evidencias.sh [1.1a | 1.1b | 1.2a | 1.2b]" ;;
esac
