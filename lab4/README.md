# Laboratorio 4 — Dashboard de Monitoreo SOC (Grafana)

**Herramienta elegida:** Opción **B — Grafana OSS 10+** con datasource
**Elasticsearch** apuntando al índice `wazuh-alerts-*` del Wazuh Indexer.
**Justificación:** Grafana se integra directo sobre el Indexer de Wazuh (que es
OpenSearch/Elasticsearch), permite las 4 visualizaciones pedidas, exportar el
dashboard como JSON versionable y definir alertas de umbral nativas.

## Archivos de este laboratorio

| Archivo | Contenido |
|---|---|
| `dashboard_soc.json` | Export del dashboard "SOC - Monitor de Seguridad" (V1–V4 + panel de texto del autor + V5 para exportar CSV). Rango global 24 h. |
| `datasource_config.json` | Provisioning del datasource Elasticsearch (Tarea 4.1). |
| `alert_rule_soc.yaml` | Regla de alerta de umbral: nivel ≥ 10 supera 5 eventos en 5 min (Tarea 4.4). |
| `evidencias/herramienta_usada.txt` | Nombre, versión y URL del servicio. |

> Estos artefactos son **reproducibles**: al importarlos sobre un Grafana
> conectado a Wazuh generan el dashboard y la alerta tal como pide la rúbrica.
> Las capturas SCR-4.x deben tomarse de **ese** Grafana en ejecución (VM/EC2).

## Despliegue (VM Linux o EC2)

```bash
# 1) Grafana OSS
sudo apt install -y apt-transport-https software-properties-common
wget -q -O - https://apt.grafana.com/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/grafana.gpg
echo "deb [signed-by=/usr/share/keyrings/grafana.gpg] https://apt.grafana.com stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt update && sudo apt install -y grafana
sudo systemctl enable --now grafana-server        # escucha en :3000

# 2) Datasource (UI): Connections > Data sources > Add > Elasticsearch
#    URL https://localhost:9200 · index wazuh-alerts-* · time field @timestamp
#    Skip TLS verify ON · basic auth admin / <contraseña del indexer>
#    (equivale a datasource_config.json)

# 3) Importar el dashboard: Dashboards > New > Import > Upload JSON
#    -> dashboard_soc.json  y seleccionar el datasource creado.

# 4) Alerta de umbral (Tarea 4.4): ver alert_rule_soc.yaml
#    Opción UI: Alerting > Alert rules > New (query rule.level:>=10, threshold > 5, for 5m)
```

## Captura de evidencias (mostrar hostname/IP y fecha en cada screenshot)

| Código | Qué debe verse | Dónde |
|---|---|---|
| **SCR-4.1** | Datasource conectado ("Save & test" OK) y ≥ 1 evento. Exportar 20 registros: panel **V5 → Inspect → Data → Download CSV** | `evidencias/SCR-4.1_fuente_datos.png` (+ el CSV) |
| **SCR-4.2** | Las 4 visualizaciones V1–V4 con datos | `evidencias/SCR-4.2_visualizaciones.png` |
| **SCR-4.3** | Dashboard completo "SOC - Monitor de Seguridad" con el panel de texto del autor y rango 24 h | `evidencias/SCR-4.3_dashboard.png` |
| **SCR-4.4** | La regla de alerta con condición (nivel ≥ 10 > 5 en 5m) y contact point | `evidencias/SCR-4.4_alerta.png` |

> Para poblar el dashboard con datos reales antes de capturar, dispara alertas en
> Wazuh (p. ej. `sudo bash ../lab2/generar_evidencia_lab2.sh`) y espera 1–2 min.

## Pendiente antes de entregar

- [ ] Rellenar `<IP_VM>` / `<IP_PUBLICA_EC2>` en `evidencias/herramienta_usada.txt`.
- [ ] En `alert_rule_soc.yaml`, reemplazar `<UID_DATASOURCE_ELASTICSEARCH>` por el UID real (solo si se usa provisioning; no hace falta si se crea la alerta por UI).
- [ ] Capturar SCR-4.1 … SCR-4.4 desde el Grafana en ejecución.
