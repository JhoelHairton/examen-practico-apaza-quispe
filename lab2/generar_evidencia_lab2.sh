#!/bin/bash
# =============================================================================
# generar_evidencia_lab2.sh  —  Tarea 2.3 (Prueba y evidencia) del Laboratorio 2
# Evaluación Práctica Final — Seguridad Informática (Unidad IV)
#
# Automatiza el flujo completo de la Tarea 2.3 en la VM con Wazuh y deja la
# salida lista para capturar el screenshot SCR-2.3:
#   1) Reinicia wazuh-manager.
#   2) Simula el ataque de fuerza bruta (simular_bruteforce.sh).
#   3) Espera a que analysisd procese los eventos.
#   4) Extrae de /var/ossec/logs/alerts/alerts.log la(s) alerta(s) de la
#      regla 100001 (nivel 10, brute_force) con la IP atacante.
# Imprime tu NOMBRE y la FECHA/HORA (requisito del examen) y pone el nombre
# en la barra de título de la terminal. Toma la captura al terminar.
#
# EJECUTAR EN LA VM LINUX CON WAZUH, como root:
#   sudo bash lab2/generar_evidencia_lab2.sh [IP_ATACANTE] [NUMERO_INTENTOS]
# Ejemplos:
#   sudo bash lab2/generar_evidencia_lab2.sh                 # 45.33.32.156, 15
#   sudo bash lab2/generar_evidencia_lab2.sh 45.33.32.156 20
# =============================================================================

NOMBRE="Jhoel Apaza Quispe"
ATTACKER_IP="${1:-45.33.32.156}"
COUNT="${2:-15}"
ALERTS="/var/ossec/logs/alerts/alerts.log"

cd "$(dirname "$0")" || exit 1

# Nombre en la BARRA DE TÍTULO de la terminal (requisito del examen)
printf '\033]0;%s — Examen Seguridad Informatica (Lab 2)\007' "$NOMBRE"

banner () {
  echo "=================================================================="
  echo "  Estudiante : $NOMBRE"
  echo "  Fecha/hora : $(date '+%Y-%m-%d %H:%M:%S')"
  echo "  Evidencia  : $1"
  echo "=================================================================="
}

# --- Comprobaciones previas -------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  echo "[ERROR] Ejecuta con sudo (se reinicia el manager y se lee alerts.log)."
  echo "        sudo bash lab2/generar_evidencia_lab2.sh $ATTACKER_IP $COUNT"
  exit 1
fi
if [ ! -f "$ALERTS" ]; then
  echo "[ERROR] No existe $ALERTS. ¿Está instalado y activo Wazuh Manager?"
  exit 1
fi

# --- Flujo de la Tarea 2.3 --------------------------------------------------
echo "[1/4] Reiniciando wazuh-manager..."
systemctl restart wazuh-manager
sleep 5

echo "[2/4] Simulando fuerza bruta SSH desde $ATTACKER_IP ($COUNT intentos)..."
bash simular_bruteforce.sh "$ATTACKER_IP" "$COUNT" >/dev/null 2>&1

echo "[3/4] Esperando a que analysisd correlacione los eventos..."
sleep 6

echo "[4/4] Buscando alertas de la regla 100001 en alerts.log..."
echo

# Cada alerta es un bloque separado por línea en blanco (modo párrafo de awk).
ALERTAS_100001="$(awk -v RS='' '/Rule: 100001 /{print; print ""}' "$ALERTS")"
N="$(printf '%s' "$ALERTAS_100001" | grep -c 'Rule: 100001 ')"

banner "SCR-2.3 — alerta brute force SSH (rule.id 100001, nivel 10)"
echo
if [ "$N" -gt 0 ]; then
  echo ">>> $N alerta(s) de FUERZA BRUTA detectadas para $ATTACKER_IP <<<"
  echo
  # Muestra la última alerta disparada (bloque completo: rule.id, nivel, IP).
  printf '%s\n' "$ALERTAS_100001" | tail -n 25
  echo
  echo "[OK] La regla 100001 disparó correctamente. Captura esta pantalla como"
  echo "     lab2/evidencias/SCR-2.3_alerta_disparada.png"
else
  echo "[!] No se encontraron alertas de la regla 100001 todavía."
  echo "    Revisa manualmente con:"
  echo "      sudo tail -f $ALERTS"
  echo "      sudo grep -n '$ATTACKER_IP' $ALERTS | tail"
  echo "    y confirma que las reglas están copiadas en /var/ossec/etc/rules/"
  echo "    y que 'systemctl status wazuh-manager' está active (running)."
fi
