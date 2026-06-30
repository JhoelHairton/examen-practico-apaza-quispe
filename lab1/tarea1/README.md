# Tarea 1.1 — Parseo y estadísticas de `auth.log` (SSH)

**Laboratorio 1 · Análisis Forense de Logs con Python** · Autor: Jhoel Apaza Quispe

## Objetivo
Detectar intentos de autenticación SSH fallidos, contarlos por IP de origen,
generar un ranking de las 10 IPs más activas, alertar de posibles ataques de
fuerza bruta (> 50 intentos) y exportar el resultado a JSON.

## Recursos utilizados
| Recurso | Descripción |
|---|---|
| `analizar_ssh.py` | Script de análisis (parseo con expresiones regulares + `collections.Counter`) |
| `auth.log` | Log de entrada: 500 líneas de autenticación SSH |

## Ejecución
```bash
python analizar_ssh.py
# (o desde la raíz del repo:  python lab1/analizar_ssh.py)
```

## Resultados obtenidos
- **253** intentos fallidos totales desde **35** IPs únicas.
- **2 IPs** superan el umbral de 50 intentos y disparan alerta de fuerza bruta:
  - `45.33.32.156` → **120** intentos
  - `193.32.162.55` → **58** intentos

| Archivo | Contenido |
|---|---|
| `reporte_ssh.json` | Resultado estructurado (total, IPs sospechosas con flag de alerta) |
| `salida_consola.txt` | Captura de la salida real del script (ranking + líneas `[ALERTA]`) |

> Evidencia requerida: **SCR-1.1a** (ejecución con `[ALERTA]` visible) y
> **SCR-1.1b** (`cat reporte_ssh.json`).
