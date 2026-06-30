#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
predecir.py  —  Laboratorio 3.4 (Inferencia)
Evaluación Práctica Final — Seguridad Informática (Unidad IV)
Autor: Jhoel AQ

Carga el modelo serializado (modelo_anomalias.pkl), recibe un CSV de tráfico
nuevo, aplica el MISMO feature engineering y escalado del entrenamiento y lista
por consola los registros clasificados como ANOMALÍA junto con su score.

Uso:
    python predecir.py nuevo_trafico.csv
"""

import sys
from pathlib import Path

import joblib
import pandas as pd

from preprocesamiento import construir_features

BASE_DIR = Path(__file__).resolve().parent
MODELO = BASE_DIR / "modelo_anomalias.pkl"

COLS_MOSTRAR = ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol",
                "bytes_sent", "bytes_recv", "duration_sec", "packets"]


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit("Uso: python predecir.py <archivo.csv>")

    ruta_csv = Path(sys.argv[1])
    if not ruta_csv.exists():
        sys.exit(f"[ERROR] No existe el archivo CSV: {ruta_csv}")
    if not MODELO.exists():
        sys.exit(f"[ERROR] No se encontró {MODELO.name}. "
                 f"Ejecute primero el notebook deteccion_anomalias.ipynb.")

    # --- Carga del bundle (modelo + scaler + features + medianas + umbral) ---
    bundle = joblib.load(MODELO)
    model = bundle["model"]
    scaler = bundle["scaler"]
    features = bundle["features"]
    medianas = bundle["medianas"]
    umbral = bundle["umbral"]

    # --- Preprocesamiento idéntico al de entrenamiento ---
    df = pd.read_csv(ruta_csv)
    X, _ = construir_features(df, medianas=medianas)
    # Se conserva el nombre de las columnas para que el modelo no emita avisos.
    X_scaled = pd.DataFrame(scaler.transform(X[features]),
                            columns=features, index=df.index)

    # --- Predicción ---
    scores = model.decision_function(X_scaled)
    df_out = df.copy()
    df_out["anomaly_score"] = scores.round(4)
    # Clasificación con el umbral óptimo (maximiza F1) guardado en el modelo.
    df_out["es_anomalia"] = scores < umbral

    anomalias = df_out[df_out["es_anomalia"]].sort_values("anomaly_score")

    # --- Reporte por consola ---
    print("=" * 78)
    print("  DETECCIÓN DE ANOMALÍAS — predecir.py")
    print("=" * 78)
    print(f"  Modelo        : {MODELO.name}")
    print(f"  Archivo       : {ruta_csv.name}")
    print(f"  Registros     : {len(df_out)}")
    print(f"  Umbral usado  : {umbral:.4f}  (decision_function < umbral => anomalía)")
    print(f"  Anomalías     : {len(anomalias)} "
          f"({100 * len(anomalias) / len(df_out):.1f} %)")
    print("=" * 78)

    if anomalias.empty:
        print("\n  No se detectaron anomalías en el tráfico analizado.")
        return

    cols = [c for c in COLS_MOSTRAR if c in anomalias.columns] + ["anomaly_score"]
    print("\n  >>> REGISTROS CLASIFICADOS COMO ANOMALÍA (ordenados por score) <<<\n")
    with pd.option_context("display.max_rows", None,
                           "display.width", 200,
                           "display.max_columns", None):
        print(anomalias[cols].to_string(index=False))


if __name__ == "__main__":
    main()
