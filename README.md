# Examen Práctico Final — Seguridad Informática (Unidad IV)

**Monitoreo de Seguridad, SIEM e Inteligencia Artificial**

| | |
|---|---|
| **Escuela** | Ingeniería de Sistemas — Ciclo IX |
| **Curso** | Seguridad Informática |
| **Autor** | Jhoel AQ |
| **Repositorio** | https://github.com/abelthf/examen_final_seguridad_informatica |

> Sistema de monitoreo SOC de extremo a extremo: análisis forense de logs con
> Python, reglas de correlación en Wazuh, detección de anomalías con Machine
> Learning (Isolation Forest) y un dashboard de monitoreo en Grafana.

---

## 1. Entorno de trabajo

Desarrollo y pruebas sobre **máquina virtual Linux Ubuntu 22.04 LTS**
(VirtualBox / VMware), 4 vCPU · 8 GB RAM · 50 GB disco.

> Los Laboratorios 1 y 3 (Python / ML) se ejecutan en cualquier SO; los
> Laboratorios 2 y 4 (Wazuh / Grafana) requieren el host Linux.

### Versiones de herramientas

| Herramienta | Versión | Uso |
|---|---|---|
| Python | 3.11.7 | Labs 1 y 3 |
| pandas | 2.2.1 | Análisis de datos |
| numpy | 1.26.4 | Cálculo numérico |
| matplotlib | 3.10.x | Gráficas Lab 1 |
| seaborn | 0.13.2 | Heatmap / matriz de confusión |
| scikit-learn | 1.4+ | Isolation Forest |
| joblib | 1.3+ | Serialización del modelo |
| Jupyter / nbconvert | 7.x | Notebook Lab 3 |
| Wazuh (Manager + Indexer + Dashboard) | 4.9.x | Lab 2 — SIEM |
| Grafana OSS | 10.x | Lab 4 — Dashboard |

### Instalación del entorno

```bash
# --- Python (Labs 1 y 3) ---
sudo apt update && sudo apt install -y python3 python3-pip python3-venv
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# --- Wazuh All-in-One (Lab 2): Manager + Indexer + Dashboard ---
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
sudo bash ./wazuh-install.sh -a          # instala el stack completo
# La contraseña del usuario 'admin' se imprime al final de la instalación.

# --- Grafana OSS (Lab 4) ---
sudo apt install -y apt-transport-https software-properties-common
wget -q -O - https://apt.grafana.com/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/grafana.gpg
echo "deb [signed-by=/usr/share/keyrings/grafana.gpg] https://apt.grafana.com stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt update && sudo apt install -y grafana
sudo systemctl enable --now grafana-server   # escucha en el puerto 3000
```

---

## 2. Estructura del repositorio

```
examen_final_seguridad_informatica/
├── README.md                  ← este archivo
├── requirements.txt
├── lab1/                      ← Análisis forense de logs (Python)
│   ├── analizar_ssh.py        · 1.1 brute force SSH  -> reporte_ssh.json
│   ├── analizar_web.py        · 1.2 escaneo + SQLi   -> reporte_web.json
│   ├── visualizar.py          · 1.3 3 gráficas PNG
│   ├── auth.log / access.log  · datasets de entrada
│   ├── reporte_ssh.json / reporte_web.json   · salidas generadas
│   ├── graficas/              · top10_ssh.png, timeline_http.png, heatmap_http.png
│   └── evidencias/            · SCR-1.x (screenshots a capturar)
├── lab2/                      ← Reglas de correlación Wazuh
│   ├── local_rules_ssh.xml    · 2.1 brute force SSH (rule 100001)
│   ├── local_rules_exfil.xml  · 2.2 exfiltración (reglas 100010/11/12)
│   ├── simular_bruteforce.sh  · generador de tráfico de prueba
│   └── evidencias/            · SCR-2.x
├── lab3/                      ← Detección de anomalías (ML)
│   ├── deteccion_anomalias.ipynb   · 3.1–3.4 (ejecutado)
│   ├── preprocesamiento.py    · feature engineering compartido
│   ├── predecir.py            · 3.4 inferencia sobre CSV nuevo
│   ├── network_traffic.csv    · dataset (10 000 registros)
│   ├── modelo_anomalias.pkl   · modelo serializado (generado)
│   ├── nuevo_trafico.csv       · muestra de prueba (generada)
│   └── evidencias/            · SCR-3.x
└── lab4/                      ← Dashboard de monitoreo (Grafana)
    ├── dashboard_soc.json     · export importable (4 visualizaciones)
    ├── datasource_config.json · provisioning del datasource Elasticsearch
    └── evidencias/            · herramienta_usada.txt + SCR-4.x
```

---

## 3. Reproducción de cada laboratorio

### Lab 1 — Análisis Forense de Logs (Python)

```bash
# Desde la raíz del repositorio:
python lab1/analizar_ssh.py     # -> imprime ranking + [ALERTA] y crea reporte_ssh.json
python lab1/analizar_web.py     # -> escaneo + SQLi + errores y crea reporte_web.json
python lab1/visualizar.py       # -> crea lab1/graficas/*.png
```

Resultados verificados con los datasets provistos:
- **SSH:** 253 intentos fallidos · IPs en alerta (>50): **45.33.32.156 (120)** y **193.32.162.55 (58)**.
- **Web:** escaneo de directorios desde **45.33.32.156** (32 peticiones/60 s) · **8** intentos de SQLi desde **193.32.162.55** · 30 IPs con errores 4xx/5xx.

### Lab 2 — Reglas de Correlación Wazuh

```bash
# 1) Copiar las reglas al manager
sudo cp lab2/local_rules_ssh.xml  /var/ossec/etc/rules/
sudo cp lab2/local_rules_exfil.xml /var/ossec/etc/rules/
sudo chown wazuh:wazuh /var/ossec/etc/rules/local_rules_*.xml

# 2) Validar la sintaxis XML
xmllint --noout /var/ossec/etc/rules/local_rules_ssh.xml && echo OK
xmllint --noout /var/ossec/etc/rules/local_rules_exfil.xml && echo OK

# 3) Reiniciar el manager y probar
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager           # debe verse active (running)
sudo bash lab2/simular_bruteforce.sh 45.33.32.156 15

# 4) Verificar que la regla 100001 disparó
sudo tail -n 40 /var/ossec/logs/alerts/alerts.log
sudo grep -E "100001|brute_force" /var/ossec/logs/alerts/alerts.log | tail
```

- **Regla 100001** (nivel 10): 10+ fallos SSH de la misma IP en 60 s → fuerza bruta.
- **Reglas 100010/100011/100012** (nivel 14): exfiltración = login off-hours + transferencia saliente > 500 MB del mismo host.

### Lab 3 — Detección de Anomalías (ML)

```bash
# Ejecutar el notebook completo (genera modelo_anomalias.pkl y nuevo_trafico.csv)
cd lab3
jupyter notebook deteccion_anomalias.ipynb       # o: Run All en la interfaz
# Reproducción headless equivalente:
python -m nbconvert --to notebook --execute --inplace deteccion_anomalias.ipynb

# Inferencia sobre tráfico nuevo
python predecir.py nuevo_trafico.csv
```

Métricas obtenidas con Isolation Forest (`contamination=0.05`, `n_estimators=100`,
`random_state=42`): **Precision 0.82 · Recall 0.82 · F1 0.82** (F1 hasta **0.85**
con el umbral óptimo de la curva umbral-F1). Cumple el criterio F1 > 0.7.

### Lab 4 — Dashboard de Monitoreo (Grafana)

1. Conectar el datasource: **Connections → Data sources → Add → Elasticsearch**
   (URL `https://localhost:9200`, índice `wazuh-alerts-*`, time field `@timestamp`,
   *Skip TLS verify*, usuario `admin`). Ver `lab4/datasource_config.json`.
2. Importar el dashboard: **Dashboards → New → Import → Upload JSON file →**
   `lab4/dashboard_soc.json` y seleccionar el datasource creado.
3. Verificar las 4 visualizaciones (V1 barras, V2 tabla, V3 línea, V4 pie) y el
   rango global de 24 h.
4. Alerta (Tarea 4.4): **Alerting → Alert rules → New** con condición
   `count(rule.level >= 10) > 5` en `5m`, notificando a un *contact point*
   (webhook/email).

---

## 4. Checklist de evidencias (screenshots)

> Cada captura debe mostrar **fecha/hora del sistema** y el **nombre del autor**
> visible (prompt de terminal o barra de título).

| Código | Cómo generarla |
|---|---|
| SCR-1.1a | Terminal con `python lab1/analizar_ssh.py` y las líneas `[ALERTA]` visibles |
| SCR-1.1b | `cat lab1/reporte_ssh.json` |
| SCR-1.2a | Terminal con `python lab1/analizar_web.py` (escaneo + SQLi visibles) |
| SCR-1.2b | `cat lab1/reporte_web.json` |
| SCR-1.3* | Las 3 PNG ya están en `lab1/graficas/` |
| SCR-2.1 | `systemctl status wazuh-manager` → active (running) |
| SCR-2.2 | `xmllint --noout local_rules_ssh.xml && echo OK` |
| SCR-2.3 | Extracto de `/var/ossec/logs/alerts/alerts.log` con la alerta brute-force (IP + rule.id 100001) |
| SCR-3.1 | Notebook: celdas de EDA + histogramas |
| SCR-3.2 | Notebook: Precision/Recall/F1 + matriz de confusión |
| SCR-3.3 | Notebook: curva umbral-F1 + tabla Top 10 anomalías |
| SCR-3.4 | Terminal con `python predecir.py nuevo_trafico.csv` |
| SCR-4.1 | Grafana con el datasource conectado y ≥ 1 evento |
| SCR-4.2 | Las 4 visualizaciones V1–V4 |
| SCR-4.3 | Dashboard "SOC - Monitor de Seguridad" con datos del autor |
| SCR-4.4 | Regla de alerta configurada (umbral + notificación) |

Guardar cada imagen en la carpeta `evidencias/` del laboratorio correspondiente,
con el nombre indicado en la guía del examen (p. ej. `SCR-1.1a_ssh_ejecucion.png`).
