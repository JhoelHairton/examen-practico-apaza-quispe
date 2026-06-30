#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
preprocesamiento.py  —  Laboratorio 3 (utilidades compartidas)
Evaluación Práctica Final — Seguridad Informática (Unidad IV)
Autor: Jhoel AQ

Centraliza el feature engineering para que el notebook de entrenamiento
(deteccion_anomalias.ipynb) y el script de inferencia (predecir.py) construyan
EXACTAMENTE las mismas variables. Así se evita el "training/serving skew".
"""

import numpy as np
import pandas as pd

# Columnas numéricas base presentes en el CSV original.
COLUMNAS_BASE = ["dst_port", "bytes_sent", "bytes_recv", "duration_sec", "packets"]

# Features finales (en orden) que recibe el modelo. El scaler y el modelo se
# entrenan sobre estas columnas; predecir.py debe reconstruirlas igual.
COLUMNAS_FEATURES = [
    "dst_port", "bytes_sent", "bytes_recv", "duration_sec", "packets",
    "bytes_totales", "ratio_bytes", "bytes_por_segundo",
    "paquetes_por_segundo", "bytes_por_paquete",
    "proto_TCP", "proto_UDP", "proto_ICMP",
]

# Variables con cola muy pesada: se les aplica log1p para comprimir los
# atípicos extremos sin eliminarlos (las anomalías deben conservarse).
COLUMNAS_LOG = [
    "bytes_sent", "bytes_recv", "packets", "bytes_totales", "ratio_bytes",
    "bytes_por_segundo", "paquetes_por_segundo", "bytes_por_paquete",
]


def construir_features(df: pd.DataFrame, medianas: dict | None = None):
    """Construye la matriz de features a partir del DataFrame crudo.

    Parámetros
    ----------
    df : DataFrame con (al menos) las columnas base + 'protocol'.
    medianas : dict opcional {columna: mediana}. En entrenamiento se deja en
        None y se calcula desde los datos; en inferencia se pasan las medianas
        guardadas del entrenamiento para imputar igual.

    Devuelve
    --------
    (X, medianas) : X = DataFrame con COLUMNAS_FEATURES; medianas usadas.
    """
    df = df.copy()

    # 1) Coerción a numérico y tratamiento de NULOS (imputación por mediana).
    for c in COLUMNAS_BASE:
        df[c] = pd.to_numeric(df.get(c), errors="coerce")
    if medianas is None:
        medianas = df[COLUMNAS_BASE].median(numeric_only=True).to_dict()
    df[COLUMNAS_BASE] = df[COLUMNAS_BASE].fillna(value=medianas)

    # 2) Saneamiento: no existen bytes/paquetes/duraciones negativos.
    for c in ["bytes_sent", "bytes_recv", "duration_sec", "packets"]:
        df[c] = df[c].clip(lower=0)

    # 3) Feature engineering (variables derivadas).
    eps = 1e-6
    df["bytes_totales"] = df["bytes_sent"] + df["bytes_recv"]
    df["ratio_bytes"] = df["bytes_sent"] / (df["bytes_recv"] + 1)
    df["bytes_por_segundo"] = df["bytes_totales"] / (df["duration_sec"] + eps)
    df["paquetes_por_segundo"] = df["packets"] / (df["duration_sec"] + eps)
    df["bytes_por_paquete"] = df["bytes_totales"] / (df["packets"] + 1)

    # 4) Tratamiento de atípicos extremos: log1p en las colas pesadas.
    for c in COLUMNAS_LOG:
        df[c] = np.log1p(df[c])

    # 5) Codificación one-hot del protocolo (TCP/UDP/ICMP).
    proto = df.get("protocol", pd.Series(["NA"] * len(df))).astype(str).str.upper()
    df["proto_TCP"] = (proto == "TCP").astype(int)
    df["proto_UDP"] = (proto == "UDP").astype(int)
    df["proto_ICMP"] = (proto == "ICMP").astype(int)

    return df[COLUMNAS_FEATURES], medianas
