# Tarea 1.2 — Análisis de `access.log` (Web / Apache)

**Laboratorio 1 · Análisis Forense de Logs con Python** · Autor: Jhoel Apaza Quispe

## Objetivo
Parsear el log de acceso Apache (Combined Log Format) y detectar tres amenazas:
escaneo de directorios, errores 4xx/5xx agrupados por IP e intentos de
SQL Injection en las URLs.

## Recursos utilizados
| Recurso | Descripción |
|---|---|
| `analizar_web.py` | Script de análisis (regex Combined Log Format + ventana deslizante de 60 s + firmas SQLi) |
| `access.log` | Log de entrada: 1000 líneas de acceso HTTP |

## Ejecución
```bash
python analizar_web.py
# (o desde la raíz del repo:  python lab1/analizar_web.py)
```

## Resultados obtenidos
- **Escaneo de directorios:** `45.33.32.156` con **32 peticiones** (19 rutas
  distintas) en menos de 60 s → posible escaneo (user-agent Nikto).
- **SQL Injection:** **8** intentos desde `193.32.162.55`
  (ej. `/login?user=admin'--&pass=x`, `/search?q='`).
- **Errores 4xx/5xx:** **30** IPs con errores; la que más acumula es
  `45.33.32.156` (47 errores: 44 de tipo 4xx y 3 de tipo 5xx).

> **Criterio aplicado:** la consigna dice "más de 20 peticiones a rutas distintas
> en < 60 s". El umbral se evalúa sobre el número de **peticiones** (32 > 20);
> el reporte también indica las rutas distintas del pico (19).

| Archivo | Contenido |
|---|---|
| `reporte_web.json` | Resultado estructurado (escaneo, SQLi, errores por IP) |
| `salida_consola.txt` | Captura de la salida real del script |

> Evidencia requerida: **SCR-1.2a** (ejecución con escaneo y SQLi visibles) y
> **SCR-1.2b** (`cat reporte_web.json`).
