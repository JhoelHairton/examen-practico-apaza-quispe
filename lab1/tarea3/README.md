# Tarea 1.3 — Visualización

**Laboratorio 1 · Análisis Forense de Logs con Python** · Autor: Jhoel Apaza Quispe

## Objetivo
Generar 3 gráficas (con `matplotlib` / `seaborn`) a partir de los logs SSH y web,
guardadas como imágenes PNG con títulos y etiquetas.

## Recursos utilizados
| Recurso | Descripción |
|---|---|
| `visualizar.py` | Script de graficación (reutiliza los parsers de las tareas 1.1 y 1.2) |
| `auth.log` / `access.log` | Logs de entrada (en `lab1/`) |

## Ejecución
```bash
python visualizar.py
# (o desde la raíz del repo:  python lab1/visualizar.py)
```

## Resultados obtenidos (gráficas generadas)
| Archivo | Tipo | Descripción |
|---|---|---|
| `top10_ssh.png` | Barras | Top 10 IPs con más intentos SSH fallidos |
| `timeline_http.png` | Línea | Número de peticiones HTTP por hora del día |
| `heatmap_http.png` | Mapa de calor | Peticiones HTTP por hora y código (200/301/404/500) |

Hallazgo visual: el heatmap muestra un pico marcado de errores 404 alrededor de
las **03:00 h**, coincidente con la actividad del escáner `45.33.32.156`.

> Evidencia requerida: **SCR-1.3** — las 3 gráficas se entregan directamente
> como archivos PNG.
