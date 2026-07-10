from flask import Flask, request, jsonify, send_file
from pymongo import MongoClient
import httpx
import json
import os
import math
import concurrent.futures
from datetime import datetime, timezone
from io import BytesIO

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                  TableStyle, HRFlowable)
from reportlab.lib.enums import TA_LEFT

app = Flask(__name__)


@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
    return response



# CONFIGURACIÓN — todo desde variables de entorno
MONGODB_URI = os.environ.get("MONGODB_URI", "")
VT_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
ABUSE_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
IPINFO_KEY = os.environ.get("IPINFO_TOKEN", "")
SHODAN_KEY = os.environ.get("SHODAN_API_KEY", "")
URLSCAN_KEY = os.environ.get("URLSCAN_API_KEY", "")
THREATFOX_KEY = os.environ.get("THREATFOX_API_KEY", "")

client_mongo = MongoClient(MONGODB_URI)
db = client_mongo.threatops


# DETECTOR DE TIPO DE IOC
import re
import base64


def detectar_tipo_ioc(valor):
    valor = valor.strip()

    # URL — empieza con http:// o https://
    if re.match(r"^https?://", valor, re.IGNORECASE):
        return "url"

    # IP (IPv4 simple)
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", valor):
        return "ip"

    # Dominio — tiene al menos un punto y no es IP
    if re.match(r"^[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", valor):
        return "domain"

    return "ip"  # por defecto, si no matchea nada


# ENRIQUECIMIENTO — 3 APIs en paralelo
def enriquecer_ip(ioc):

    def get_vt():
        try:
            r = httpx.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
                headers={"x-apikey": VT_KEY}, timeout=8
            )
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "fuente": "VirusTotal",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "status": "ok"
            }
        except Exception:
            return {"fuente": "VirusTotal", "status": "error"}

    def get_abuse():
        try:
            r = httpx.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSE_KEY, "Accept": "application/json"},
                params={"ipAddress": ioc, "maxAgeInDays": 90}, timeout=8
            )
            d = r.json().get("data", {})
            return {
                "fuente": "AbuseIPDB",
                "confidence_score": d.get("abuseConfidenceScore", 0),
                "total_reports": d.get("totalReports", 0),
                "country": d.get("countryCode", "N/A"),
                "isp": d.get("isp", "N/A"),
                "status": "ok"
            }
        except Exception:
            return {"fuente": "AbuseIPDB", "status": "error"}

    def get_ipinfo():
        try:
            r = httpx.get(
                f"https://ipinfo.io/{ioc}/json",
                headers={"Authorization": f"Bearer {IPINFO_KEY}"}, timeout=8
            )
            d = r.json()
            return {
                "fuente": "IPInfo",
                "ciudad": d.get("city", "N/A"),
                "pais": d.get("country", "N/A"),
                "org": d.get("org", "N/A"),
                "ubicacion": d.get("loc", "N/A"),
                "status": "ok"
            }
        except Exception:
            return {"fuente": "IPInfo", "status": "error"}

    def get_shodan():
        try:
            r = httpx.get(
                f"https://api.shodan.io/shodan/host/{ioc}",
                params={"key": SHODAN_KEY}, timeout=5
            )
            if r.status_code == 404:
                return {
                    "fuente": "Shodan",
                    "puertos_abiertos": [],
                    "servicios": [],
                    "vulnerabilidades": [],
                    "status": "ok",
                    "nota": "Sin datos indexados para este host"
                }
            d = r.json()
            servicios = []
            for item in d.get("data", [])[:5]:
                servicio = item.get("product", "") or item.get("_shodan", {}).get("module", "desconocido")
                servicios.append(f"{item.get('port')}/{servicio}")
            return {
                "fuente": "Shodan",
                "puertos_abiertos": d.get("ports", []),
                "servicios": servicios,
                "vulnerabilidades": list(d.get("vulns", [])),
                "org": d.get("org", "N/A"),
                "sistema_operativo": d.get("os") or "N/A",
                "status": "ok"
            }
        except Exception:
            return {"fuente": "Shodan", "status": "error"}

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        future_vt = executor.submit(get_vt)
        future_abuse = executor.submit(get_abuse)
        future_ipinfo = executor.submit(get_ipinfo)
        future_shodan = executor.submit(get_shodan)

        vt = future_vt.result()
        abuse = future_abuse.result()
        ipinfo = future_ipinfo.result()
        shodan = future_shodan.result()

    score = 0

    if vt.get("status") == "ok":
        total_motores = vt["malicious"] + vt["suspicious"] + vt["harmless"] + vt.get("undetected", 0)
        if total_motores > 0:
            ratio_malicioso = vt["malicious"] / total_motores
            # raiz cuadrada para que incluso un % parcial de detecciones pese
            score += math.sqrt(ratio_malicioso) * 65
        score += vt["suspicious"] * 1.5

    if abuse.get("status") == "ok":
        score += abuse["confidence_score"] * 0.35

    if shodan.get("status") == "ok" and shodan.get("vulnerabilidades"):
        score += len(shodan["vulnerabilidades"]) * 3

    score = min(round(score), 100)

    return {"fuentes": [vt, abuse, ipinfo, shodan], "score": score}


def enriquecer_domain(dominio):
    def get_vt_domain():
        try:
            r = httpx.get(
                f"https://www.virustotal.com/api/v3/domains/{dominio}",
                headers={"x-apikey": VT_KEY}, timeout=8
            )
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "fuente": "VirusTotal",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputacion": attrs.get("reputation", 0),
                "categorias": list((attrs.get("categories") or {}).values())[:3],
                "status": "ok"
            }
        except Exception:
            return {"fuente": "VirusTotal", "status": "error"}

    def get_urlscan_domain():
        try:
            r = httpx.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"domain:{dominio}", "size": 5},
                headers={"API-Key": URLSCAN_KEY}, timeout=8
            )
            resultados = r.json().get("results", [])
            if not resultados:
                return {
                    "fuente": "URLScan",
                    "escaneos_encontrados": 0,
                    "status": "ok",
                    "nota": "sin escaneos previos registrados"
                }
            ultimo = resultados[0]
            return {
                "fuente": "URLScan",
                "escaneos_encontrados": len(resultados),
                "ultimo_scan_ip": ultimo.get("page", {}).get("ip", "N/A"),
                "ultimo_scan_pais": ultimo.get("page", {}).get("country", "N/A"),
                "ultimo_scan_server": ultimo.get("page", {}).get("server", "N/A"),
                "screenshot_url": ultimo.get("screenshot", ""),
                "status": "ok"
            }
        except Exception:
            return {"fuente": "URLScan", "status": "error"}

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        future_vt = executor.submit(get_vt_domain)
        future_urlscan = executor.submit(get_urlscan_domain)
        vt = future_vt.result()
        urlscan = future_urlscan.result()

    score = 0
    if vt.get("status") == "ok":
        total_motores = vt["malicious"] + vt["suspicious"] + vt["harmless"] + vt.get("undetected", 0)
        if total_motores > 0:
            ratio_malicioso = vt["malicious"] / total_motores
            score += math.sqrt(ratio_malicioso) * 70
        score += vt["suspicious"] * 1.5
        if vt.get("reputacion", 0) < 0:
            score += min(abs(vt["reputacion"]), 20)
    score = min(round(score), 100)

    return {"fuentes": [vt, urlscan], "score": score}


def enriquecer_url(url_completa):
    url_id = base64.urlsafe_b64encode(url_completa.encode()).decode().strip("=")

    def get_vt_url():
        try:
            r = httpx.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": VT_KEY}, timeout=8
            )
            if r.status_code == 404:
                # si no existe, la enviamos a analizar
                httpx.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers={"x-apikey": VT_KEY},
                    data={"url": url_completa}, timeout=8
                )
                return {
                    "fuente": "VirusTotal",
                    "status": "ok",
                    "nota": "URL enviada a analisis, aun sin resultados indexados"
                }
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "fuente": "VirusTotal",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "titulo_pagina": attrs.get("title", "N/A"),
                "status": "ok"
            }
        except Exception:
            return {"fuente": "VirusTotal", "status": "error"}

    def get_urlscan_url():
        try:
            r = httpx.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"page.url:\"{url_completa}\"", "size": 3},
                headers={"API-Key": URLSCAN_KEY}, timeout=8
            )
            resultados = r.json().get("results", [])
            if not resultados:
                return {
                    "fuente": "URLScan",
                    "escaneos_encontrados": 0,
                    "status": "ok",
                    "nota": "sin escaneos previos registrados"
                }
            ultimo = resultados[0]
            return {
                "fuente": "URLScan",
                "escaneos_encontrados": len(resultados),
                "ip": ultimo.get("page", {}).get("ip", "N/A"),
                "pais": ultimo.get("page", {}).get("country", "N/A"),
                "server": ultimo.get("page", {}).get("server", "N/A"),
                "screenshot_url": ultimo.get("screenshot", ""),
                "status": "ok"
            }
        except Exception:
            return {"fuente": "URLScan", "status": "error"}

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        future_vt = executor.submit(get_vt_url)
        future_urlscan = executor.submit(get_urlscan_url)
        vt = future_vt.result()
        urlscan = future_urlscan.result()

    score = 0
    if vt.get("status") == "ok" and "malicious" in vt:
        total_motores = vt["malicious"] + vt["suspicious"] + vt["harmless"] + vt.get("undetected", 0)
        if total_motores > 0:
            ratio_malicioso = vt["malicious"] / total_motores
            score += math.sqrt(ratio_malicioso) * 75
        score += vt["suspicious"] * 1.5
    score = min(round(score), 100)

    return {"fuentes": [vt, urlscan], "score": score}



# GENERADOR DE PDF
def generar_pdf_informe(doc_data):
    buffer = BytesIO()
    pdf = SimpleDocTemplate(
        buffer, pagesize=letter,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
        leftMargin=0.7 * inch, rightMargin=0.7 * inch
    )

    styles = getSampleStyleSheet()
    story = []

    sev = doc_data.get("severity", "UNKNOWN")
    sev_colors = {
        "LOW": colors.HexColor("#1e8449"),
        "MEDIUM": colors.HexColor("#b7950b"),
        "HIGH": colors.HexColor("#d35400"),
        "CRITICAL": colors.HexColor("#c0392b"),
        "UNKNOWN": colors.HexColor("#5d6d7e")
    }
    sev_color = sev_colors.get(sev, colors.grey)

    title_style = ParagraphStyle(
        "TitleC", parent=styles["Title"],
        fontSize=22, textColor=colors.HexColor("#0a0e14"), spaceAfter=4, alignment=TA_LEFT
    )
    sub_style = ParagraphStyle(
        "Sub", parent=styles["Normal"],
        fontSize=10, textColor=colors.HexColor("#6b7686"), spaceAfter=14
    )
    h2_style = ParagraphStyle(
        "H2", parent=styles["Heading2"],
        fontSize=13, textColor=colors.HexColor("#0a0e14"), spaceBefore=16, spaceAfter=8
    )
    body_style = ParagraphStyle(
        "Body", parent=styles["Normal"],
        fontSize=10, leading=15, textColor=colors.HexColor("#1a1a1a"), spaceAfter=8, alignment=TA_LEFT
    )
    label_style = ParagraphStyle(
        "Label", parent=styles["Normal"],
        fontSize=8, textColor=colors.HexColor("#6b7686"), spaceAfter=2
    )

    story.append(Paragraph("INFORME DE INTELIGENCIA DE AMENAZAS", title_style))
    story.append(Paragraph(
        "ThreatOps Platform &middot; Olimpia Offensive Security &middot; Clasificacion TLP:AMBER",
        sub_style
    ))
    story.append(HRFlowable(width="100%", thickness=1.5, color=sev_color, spaceAfter=14))

    fecha_str = doc_data.get("created_at", "-")
    if fecha_str and fecha_str != "-":
        fecha_str = str(fecha_str)[:19].replace("T", " ")

    meta_table = Table([
        ["INDICADOR ANALIZADO", doc_data.get("ioc_value", "-")],
        ["TIPO", (doc_data.get("ioc_type", "ip") or "ip").upper()],
        ["SEVERIDAD", sev],
        ["SCORE DE RIESGO", str(doc_data.get("score", 0)) + "/100"],
        ["CONFIANZA DEL ANALISIS", str(doc_data.get("confianza_ia", 0)) + "%"],
        ["FECHA DE ANALISIS", fecha_str],
    ], colWidths=[2.1 * inch, 4 * inch])
    meta_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#6b7686")),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#0a0e14")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, colors.HexColor("#e0e0e0")),
        ("BACKGROUND", (0, 2), (1, 2), sev_color),
        ("TEXTCOLOR", (0, 2), (1, 2), colors.white),
        ("FONTNAME", (1, 2), (1, 2), "Helvetica-Bold"),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 18))

    story.append(Paragraph("1. RESUMEN EJECUTIVO", h2_style))
    story.append(Paragraph("<b>Veredicto:</b> " + str(doc_data.get('veredicto', '-')), body_style))
    story.append(Paragraph(str(doc_data.get("narrativa", "Sin narrativa disponible.")), body_style))
    if doc_data.get("actor_probable"):
        story.append(Paragraph("<b>Actor probable:</b> " + str(doc_data.get('actor_probable')), body_style))

    # Correlación SIEM, si viene incluida
    siem = doc_data.get("correlacion_siem")
    if isinstance(siem, str):
        try:
            siem = json.loads(siem)
        except Exception:
            siem = None
    if isinstance(siem, dict) and siem.get("hay_correlacion"):
        story.append(Paragraph("<b>Correlacion SIEM:</b> " + str(siem.get("resumen", "")), body_style))

    story.append(Paragraph("2. HALLAZGOS TECNICOS POR FUENTE", h2_style))
    fuentes = doc_data.get("fuentes", [])
    if isinstance(fuentes, str):
        try:
            fuentes = json.loads(fuentes)
        except Exception:
            fuentes = []
    for f in fuentes:
        if f.get("status") != "ok":
            continue
        rows = [[k.replace("_", " ").upper(), str(v)] for k, v in f.items() if k not in ("fuente", "status")]
        t = Table([[f.get("fuente", "-"), ""]] + rows, colWidths=[2.3 * inch, 3.8 * inch])
        t.setStyle(TableStyle([
            ("SPAN", (0, 0), (1, 0)),
            ("BACKGROUND", (0, 0), (1, 0), colors.HexColor("#141a24")),
            ("TEXTCOLOR", (0, 0), (1, 0), colors.white),
            ("FONTNAME", (0, 0), (1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("TEXTCOLOR", (0, 1), (0, -1), colors.HexColor("#6b7686")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("LINEBELOW", (0, 1), (-1, -1), 0.4, colors.HexColor("#e8e8e8")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(t)
        story.append(Spacer(1, 8))

    story.append(Paragraph("3. CLASIFICACION MITRE ATT&CK", h2_style))
    story.append(Paragraph(
        "<b>Tactica / Tecnica identificada:</b> " + str(doc_data.get('mitre_tactica', 'No determinado')),
        body_style
    ))

    story.append(Paragraph("4. RECOMENDACIONES DE REMEDIACION", h2_style))
    remed = doc_data.get("remediacion", "Sin recomendaciones registradas.") or "Sin recomendaciones registradas."
    for i, accion in enumerate(str(remed).split(";"), 1):
        accion = accion.strip()
        if accion:
            story.append(Paragraph("<b>" + str(i) + ".</b> " + accion, body_style))

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Documento generado automaticamente por ThreatOps Platform. Motor de analisis: enriquecimiento multi-fuente "
        "(VirusTotal, AbuseIPDB, IPInfo) + agentes de IA nativos de n8n. Este informe es confidencial y de uso "
        "interno para el equipo de Offensive Security de Olimpia.",
        label_style
    ))

    pdf.build(story)
    buffer.seek(0)
    return buffer



# ENDPOINTS
@app.route("/")
def root():
    return jsonify({"status": "running", "plataforma": "ThreatOps v1.0", "dashboard": "/dashboard"})


@app.route("/dashboard")
def dashboard():
    try:
        with open(os.path.join(os.path.dirname(__file__), "dashboard.html"), "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "dashboard.html no encontrado en el repositorio", 404


@app.route("/enrich", methods=["POST"])
def enrich():
    data = request.json or {}
    ioc = data.get("ioc", "")

    if not ioc:
        return jsonify({"error": "IOC requerido"}), 400

    tipo = detectar_tipo_ioc(ioc)

    if tipo == "domain":
        enriquecido = enriquecer_domain(ioc)
    elif tipo == "url":
        enriquecido = enriquecer_url(ioc)
    else:
        enriquecido = enriquecer_ip(ioc)

    return jsonify({
        "ioc": ioc,
        "tipo": tipo,
        "resultado": enriquecido
    })


@app.route("/iocs")
def get_iocs():
    iocs = list(db.iocs.find({}, {"_id": 0}))
    return jsonify({"total": len(iocs), "iocs": iocs})


def get_threatfox(ioc_valor):
    try:
        r = httpx.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": THREATFOX_KEY},
            json={"query": "search_ioc", "search_term": ioc_valor},
            timeout=8
        )
        d = r.json()
        if d.get("query_status") != "ok" or not d.get("data"):
            return {
                "fuente": "ThreatFox",
                "encontrado": False,
                "status": "ok",
                "nota": "sin coincidencias en base de datos de malware conocido"
            }
        primero = d["data"][0]
        return {
            "fuente": "ThreatFox",
            "encontrado": True,
            "malware": primero.get("malware_printable", "N/A"),
            "tipo_amenaza": primero.get("threat_type_desc", "N/A"),
            "confianza": primero.get("confidence_level", 0),
            "primera_vez_visto": primero.get("first_seen", "N/A"),
            "tags": primero.get("tags") or [],
            "status": "ok"
        }
    except Exception:
        return {"fuente": "ThreatFox", "status": "error"}


def extraer_org(fuentes_raw):
    """Extrae el campo 'org' u 'organizacion' de un documento guardado, tolerando distintos formatos."""
    try:
        fuentes = fuentes_raw
        if isinstance(fuentes_raw, str):
            fuentes = json.loads(fuentes_raw)
        for f in fuentes:
            if f.get("org"):
                return f.get("org")
    except Exception:
        pass
    return None


def extraer_prefijo_red(ip):
    """Devuelve los primeros 3 octetos de una IPv4, ej: 185.220.101 de 185.220.101.45"""
    partes = ip.split(".")
    if len(partes) == 4:
        return ".".join(partes[:3])
    return None


@app.route("/hunt", methods=["POST"])
def hunt():
    data = request.json or {}
    ioc = data.get("ioc", "")
    tipo = data.get("tipo", "ip")

    if not ioc:
        return jsonify({"error": "IOC requerido"}), 400

    # 1. CORRELACION HISTORICA — todas las veces que este IOC ya fue analizado
    historial = list(db.iocs.find({"ioc_value": ioc}, {"_id": 0}).sort("created_at", 1))
    correlacion_historica = {
        "veces_consultada": len(historial),
        "primera_vez": historial[0]["created_at"] if historial else None,
        "ultima_vez": historial[-1]["created_at"] if historial else None,
        "severidades_pasadas": [h.get("severity") for h in historial]
    }

    # 2. INFRAESTRUCTURA RELACIONADA — otras IPs con la misma organizacion/ISP
    org_actual = None
    if historial:
        org_actual = extraer_org(historial[-1].get("fuentes"))

    infra_relacionada = {"organizacion": org_actual, "otros_iocs_misma_org": []}
    if org_actual:
        candidatos = list(db.iocs.find(
            {"ioc_value": {"$ne": ioc}, "severity": {"$in": ["HIGH", "CRITICAL"]}},
            {"_id": 0, "ioc_value": 1, "severity": 1, "fuentes": 1}
        ).limit(100))
        for c in candidatos:
            if extraer_org(c.get("fuentes")) == org_actual:
                infra_relacionada["otros_iocs_misma_org"].append({
                    "ioc": c["ioc_value"], "severity": c["severity"]
                })

    # 3. IOCs RELACIONADOS — mismo rango de red /24, severidad alta
    iocs_relacionados = []
    if tipo == "ip":
        prefijo = extraer_prefijo_red(ioc)
        if prefijo:
            candidatos_red = list(db.iocs.find(
                {
                    "ioc_value": {"$regex": f"^{re.escape(prefijo)}\\.", "$ne": ioc},
                    "severity": {"$in": ["HIGH", "CRITICAL"]}
                },
                {"_id": 0, "ioc_value": 1, "severity": 1}
            ).limit(20))
            iocs_relacionados = [c["ioc_value"] for c in candidatos_red]

    # 4. THREATFOX — vinculacion con malware conocido
    threatfox = get_threatfox(ioc)

    return jsonify({
        "ioc": ioc,
        "correlacion_historica": correlacion_historica,
        "infraestructura_relacionada": infra_relacionada,
        "iocs_relacionados": iocs_relacionados,
        "threatfox": threatfox
    })


@app.route("/report/pdf", methods=["POST", "GET"])
def report_pdf():
    ioc = request.args.get("ioc")
    if not ioc and request.is_json:
        ioc = (request.json or {}).get("ioc")
    if not ioc:
        return jsonify({"error": "parametro ioc requerido"}), 400

    doc_data = db.iocs.find_one({"ioc_value": ioc}, {"_id": 0}, sort=[("created_at", -1)])
    if not doc_data:
        return jsonify({"error": "IOC no encontrado, analizalo primero"}), 404

    buffer = generar_pdf_informe(doc_data)
    filename = "ThreatOps_Informe_" + ioc.replace(".", "_") + ".pdf"
    return send_file(
        buffer, mimetype="application/pdf",
        as_attachment=True, download_name=filename
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
