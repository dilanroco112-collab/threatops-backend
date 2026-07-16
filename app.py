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
                                  TableStyle, HRFlowable, KeepTogether)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.pdfgen import canvas as pdfcanvas

app = Flask(__name__)


@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
    return response


# ============================================
# CONFIGURACIÓN — todo desde variables de entorno
# ============================================
MONGODB_URI = os.environ.get("MONGODB_URI", "")
VT_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
ABUSE_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
IPINFO_KEY = os.environ.get("IPINFO_TOKEN", "")
SHODAN_KEY = os.environ.get("SHODAN_API_KEY", "")
URLSCAN_KEY = os.environ.get("URLSCAN_API_KEY", "")
THREATFOX_KEY = os.environ.get("THREATFOX_API_KEY", "")

client_mongo = MongoClient(MONGODB_URI)
db = client_mongo.threatops


# ============================================
# DETECTOR DE TIPO DE IOC
# ============================================
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


# ============================================
# ENRIQUECIMIENTO — 3 APIs en paralelo
# ============================================
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
            for item in d.get("data", [])[:8]:
                servicio = item.get("product", "") or item.get("_shodan", {}).get("module", "desconocido")
                puerto = item.get("port")

                detalle_servicio = {"puerto": puerto, "servicio": servicio}

                http_info = item.get("http")
                if http_info:
                    titulo = http_info.get("title")
                    if titulo:
                        detalle_servicio["titulo_pagina"] = titulo[:80]

                    headers_seguridad = http_info.get("headers") or {}
                    faltantes = []
                    for h in ["x-frame-options", "content-security-policy", "strict-transport-security"]:
                        if h not in {k.lower(): v for k, v in headers_seguridad.items()}:
                            faltantes.append(h)
                    if faltantes:
                        detalle_servicio["headers_seguridad_faltantes"] = faltantes

                ssl_info = item.get("ssl")
                if ssl_info:
                    cert = ssl_info.get("cert", {})
                    expira = cert.get("expires")
                    if expira:
                        detalle_servicio["certificado_ssl_expira"] = expira

                servicios.append(detalle_servicio)

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


def get_urlscan_detalle_completo(scan_uuid):
    """Consulta el endpoint de resultado completo de un escaneo ya existente en URLScan"""
    try:
        r = httpx.get(
            f"https://urlscan.io/api/v1/result/{scan_uuid}/",
            headers={"API-Key": URLSCAN_KEY}, timeout=8
        )
        if r.status_code != 200:
            return {}
        data = r.json()
        listas = data.get("lists", {})
        veredicto = data.get("verdicts", {}).get("overall", {})
        return {
            "dominios_contactados": (listas.get("domains") or [])[:10],
            "ips_contactadas": (listas.get("ips") or [])[:10],
            "certificados": (listas.get("certificates") or [])[:3],
            "urlscan_malicioso": veredicto.get("malicious", False),
            "urlscan_score": veredicto.get("score", 0)
        }
    except Exception:
        return {}


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
            respuesta = {
                "fuente": "URLScan",
                "escaneos_encontrados": len(resultados),
                "ultimo_scan_ip": ultimo.get("page", {}).get("ip", "N/A"),
                "ultimo_scan_pais": ultimo.get("page", {}).get("country", "N/A"),
                "ultimo_scan_server": ultimo.get("page", {}).get("server", "N/A"),
                "screenshot_url": ultimo.get("screenshot", ""),
                "status": "ok"
            }
            scan_uuid = ultimo.get("task", {}).get("uuid")
            if scan_uuid:
                detalle = get_urlscan_detalle_completo(scan_uuid)
                respuesta.update(detalle)
            return respuesta
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
            respuesta = {
                "fuente": "URLScan",
                "escaneos_encontrados": len(resultados),
                "ip": ultimo.get("page", {}).get("ip", "N/A"),
                "pais": ultimo.get("page", {}).get("country", "N/A"),
                "server": ultimo.get("page", {}).get("server", "N/A"),
                "screenshot_url": ultimo.get("screenshot", ""),
                "status": "ok"
            }
            scan_uuid = ultimo.get("task", {}).get("uuid")
            if scan_uuid:
                detalle = get_urlscan_detalle_completo(scan_uuid)
                respuesta.update(detalle)
            return respuesta
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


# ============================================
# GENERADOR DE PDF — nivel ingeniería
# ============================================
SEV_COLORS = {
    "LOW": colors.HexColor("#1e8449"),
    "MEDIUM": colors.HexColor("#b7950b"),
    "HIGH": colors.HexColor("#d35400"),
    "CRITICAL": colors.HexColor("#c0392b"),
    "UNKNOWN": colors.HexColor("#5d6d7e")
}


def _header_footer(canvas_obj, doc, ioc_value, sev_color, sev_label):
    canvas_obj.saveState()
    page_w, page_h = letter

    # Banda superior de color segun severidad
    canvas_obj.setFillColor(colors.HexColor("#0a0e14"))
    canvas_obj.rect(0, page_h - 0.55 * inch, page_w, 0.55 * inch, fill=1, stroke=0)
    canvas_obj.setFillColor(sev_color)
    canvas_obj.rect(0, page_h - 0.55 * inch, 0.12 * inch, 0.55 * inch, fill=1, stroke=0)

    canvas_obj.setFont("Helvetica-Bold", 10)
    canvas_obj.setFillColor(colors.white)
    canvas_obj.drawString(0.35 * inch, page_h - 0.35 * inch, "THREATOPS PLATFORM")
    canvas_obj.setFont("Helvetica", 8)
    canvas_obj.setFillColor(colors.HexColor("#9aa5b1"))
    canvas_obj.drawRightString(page_w - 0.35 * inch, page_h - 0.35 * inch, f"IOC: {ioc_value}  |  TLP:AMBER")

    # Pie de pagina
    canvas_obj.setFont("Helvetica", 7.5)
    canvas_obj.setFillColor(colors.HexColor("#8a94a0"))
    canvas_obj.drawString(0.7 * inch, 0.4 * inch,
        "Documento confidencial - Olimpia Offensive Security - Generado automaticamente por ThreatOps")
    canvas_obj.drawRightString(page_w - 0.7 * inch, 0.4 * inch, f"Pagina {doc.page}")
    canvas_obj.setStrokeColor(colors.HexColor("#e0e0e0"))
    canvas_obj.line(0.7 * inch, 0.55 * inch, page_w - 0.7 * inch, 0.55 * inch)

    canvas_obj.restoreState()


def generar_pdf_informe(doc_data):
    buffer = BytesIO()

    sev = doc_data.get("severity", "UNKNOWN")
    sev_color = SEV_COLORS.get(sev, colors.grey)
    ioc_value = doc_data.get("ioc_value", "-")

    pdf = SimpleDocTemplate(
        buffer, pagesize=letter,
        topMargin=0.85 * inch, bottomMargin=0.75 * inch,
        leftMargin=0.7 * inch, rightMargin=0.7 * inch
    )

    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle(
        "TitleC", parent=styles["Title"],
        fontSize=21, textColor=colors.HexColor("#0a0e14"), spaceAfter=2, alignment=TA_LEFT,
        fontName="Helvetica-Bold"
    )
    sub_style = ParagraphStyle(
        "Sub", parent=styles["Normal"],
        fontSize=9.5, textColor=colors.HexColor("#6b7686"), spaceAfter=16
    )
    h2_style = ParagraphStyle(
        "H2", parent=styles["Heading2"],
        fontSize=12.5, textColor=colors.HexColor("#0a0e14"), spaceBefore=18, spaceAfter=8,
        fontName="Helvetica-Bold", borderPadding=0
    )
    body_style = ParagraphStyle(
        "Body", parent=styles["Normal"],
        fontSize=9.7, leading=15, textColor=colors.HexColor("#1a1a1a"), spaceAfter=8, alignment=TA_LEFT
    )
    body_small = ParagraphStyle(
        "BodySmall", parent=body_style, fontSize=9, textColor=colors.HexColor("#3a4450")
    )
    label_style = ParagraphStyle(
        "Label", parent=styles["Normal"],
        fontSize=7.5, textColor=colors.HexColor("#8a94a0"), spaceAfter=2
    )
    quote_style = ParagraphStyle(
        "Quote", parent=body_style, fontSize=9.3, textColor=colors.HexColor("#2a3138"),
        leftIndent=10, borderColor=sev_color, borderWidth=0, spaceAfter=10
    )

    # ---------- TITULO ----------
    story.append(Paragraph("INFORME DE INTELIGENCIA DE AMENAZAS", title_style))
    story.append(Paragraph(
        "ThreatOps Platform &middot; Olimpia Offensive Security &middot; Analisis automatizado multi-fuente",
        sub_style
    ))

    # ---------- BLOQUE RESUMEN: score gauge + metadata ----------
    fecha_str = doc_data.get("created_at", "-")
    if fecha_str and fecha_str != "-":
        fecha_str = str(fecha_str)[:19].replace("T", " ") + " UTC"

    score_val = doc_data.get("score", 0)

    # Gauge visual simple: barra horizontal coloreada proporcional al score
    gauge_width = 3.0
    filled = (score_val / 100.0) * gauge_width
    gauge_table = Table(
        [[f"{score_val}", ""]],
        colWidths=[gauge_width * inch],
        rowHeights=[0.32 * inch]
    )
    gauge_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#eceff2")),
        ("ALIGN", (0, 0), (0, 0), "LEFT"),
        ("VALIGN", (0, 0), (0, 0), "MIDDLE"),
    ]))

    resumen_izq = Table([
        ["INDICADOR", ioc_value],
        ["TIPO", (doc_data.get("ioc_type", "ip") or "ip").upper()],
        ["FECHA DE ANALISIS", fecha_str],
        ["CONFIANZA DEL MODELO", str(doc_data.get("confianza_ia", 0)) + "%"],
    ], colWidths=[1.6 * inch, 2.9 * inch])
    resumen_izq.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 8.7),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#8a94a0")),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#0a0e14")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, colors.HexColor("#eeeeee")),
    ]))

    severidad_box = Table([
        [Paragraph(f'<font color="white"><b>{sev}</b></font>', ParagraphStyle("sevbig", fontSize=16, alignment=TA_CENTER))],
        [Paragraph(f'<font color="white">Score de riesgo: {score_val}/100</font>', ParagraphStyle("sevsmall", fontSize=9, alignment=TA_CENTER))],
    ], colWidths=[2.1 * inch], rowHeights=[0.42 * inch, 0.3 * inch])
    severidad_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), sev_color),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, 0), 6),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 8),
    ]))

    contenedor = Table([[resumen_izq, severidad_box]], colWidths=[4.6 * inch, 2.1 * inch])
    contenedor.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (1, 0), (1, 0), 12),
    ]))
    story.append(contenedor)
    story.append(Spacer(1, 4))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e0e0e0"), spaceAfter=14))

    # ---------- 1. RESUMEN EJECUTIVO ----------
    story.append(Paragraph("1&nbsp;&nbsp;RESUMEN EJECUTIVO", h2_style))
    story.append(HRFlowable(width="100%", thickness=2, color=sev_color, spaceAfter=8))
    veredicto_box = Table([[Paragraph(
        f"<b>Veredicto:</b> {doc_data.get('veredicto', '-')}", quote_style
    )]], colWidths=[6.6 * inch])
    veredicto_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f7f8fa")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e0e0")),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(veredicto_box)
    story.append(Spacer(1, 8))
    story.append(Paragraph(str(doc_data.get("narrativa", "Sin narrativa disponible.")), body_style))
    if doc_data.get("actor_probable"):
        story.append(Paragraph("<b>Actor probable:</b> " + str(doc_data.get('actor_probable')), body_style))

    # ---------- 2. CORRELACION SIEM ----------
    siem = doc_data.get("correlacion_siem")
    if isinstance(siem, str):
        try:
            siem = json.loads(siem)
        except Exception:
            siem = None
    if isinstance(siem, dict):
        story.append(Paragraph("2&nbsp;&nbsp;CORRELACION SIEM", h2_style))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#5a6a7a"), spaceAfter=8))
        hay_corr = siem.get("hay_correlacion")
        sev_camp = siem.get("severidad_campana", "LOW")
        estado_txt = "PATRON DETECTADO" if hay_corr else "SIN PATRON DETECTADO"
        estado_color = SEV_COLORS.get(sev_camp, colors.grey) if hay_corr else colors.HexColor("#1e8449")
        story.append(Paragraph(f'<font color="{estado_color.hexval()}"><b>{estado_txt}</b></font> &middot; severidad de campaña: {sev_camp}', body_style))
        story.append(Paragraph(str(siem.get("resumen", "Sin correlaciones detectadas.")), body_style))
        iocs_rel = siem.get("iocs_involucrados", [])
        if isinstance(iocs_rel, str):
            try:
                iocs_rel = json.loads(iocs_rel)
            except Exception:
                iocs_rel = []
        if iocs_rel:
            story.append(Paragraph("<b>IOCs correlacionados:</b> " + ", ".join(iocs_rel), body_small))


    # ---------- HALLAZGOS TECNICOS ----------
    num_sec = 3 if isinstance(siem, dict) else 2
    story.append(Paragraph(f"{num_sec}&nbsp;&nbsp;HALLAZGOS TECNICOS POR FUENTE", h2_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#5a6a7a"), spaceAfter=8))
    fuentes = doc_data.get("fuentes", [])
    if isinstance(fuentes, str):
        try:
            fuentes = json.loads(fuentes)
        except Exception:
            fuentes = []
    for f in fuentes:
        if f.get("status") != "ok":
            continue
        rows = [[k.replace("_", " ").upper(), str(v)[:80]] for k, v in f.items() if k not in ("fuente", "status")]
        if not rows:
            continue
        t = Table([[f.get("fuente", "-"), ""]] + rows, colWidths=[2.3 * inch, 4.3 * inch])
        t.setStyle(TableStyle([
            ("SPAN", (0, 0), (1, 0)),
            ("BACKGROUND", (0, 0), (1, 0), colors.HexColor("#141a24")),
            ("TEXTCOLOR", (0, 0), (1, 0), colors.white),
            ("FONTNAME", (0, 0), (1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.3),
            ("TEXTCOLOR", (0, 1), (0, -1), colors.HexColor("#6b7686")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("LINEBELOW", (0, 1), (-1, -1), 0.4, colors.HexColor("#e8e8e8")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(KeepTogether([t, Spacer(1, 8)]))

    # ---------- MITRE ----------
    num_sec += 1
    story.append(Paragraph(f"{num_sec}&nbsp;&nbsp;CLASIFICACION MITRE ATT&amp;CK", h2_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#5a6a7a"), spaceAfter=8))
    story.append(Paragraph(
        "<b>Tactica / Tecnica identificada:</b> " + str(doc_data.get('mitre_tactica', 'No determinado')),
        body_style
    ))

    # ---------- RECOMENDACIONES ----------
    num_sec += 1
    story.append(Paragraph(f"{num_sec}&nbsp;&nbsp;RECOMENDACIONES DE REMEDIACION", h2_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#5a6a7a"), spaceAfter=8))
    remed = doc_data.get("remediacion", "Sin recomendaciones registradas.") or "Sin recomendaciones registradas."
    for i, accion in enumerate(str(remed).split(";"), 1):
        accion = accion.strip()
        if accion:
            story.append(Paragraph(f"<b>{i}.</b> {accion}", body_style))

    story.append(Spacer(1, 16))
    story.append(Paragraph(
        "Documento generado automaticamente por ThreatOps Platform. Motor de analisis: enriquecimiento multi-fuente "
        "(VirusTotal, AbuseIPDB, IPInfo, Shodan, URLScan) + agentes de IA nativos de n8n (Analista, SIEM). "
        "Este informe es confidencial y de uso interno para el equipo de Offensive Security de Olimpia.",
        label_style
    ))

    def on_page(c, d):
        _header_footer(c, d, ioc_value, sev_color, sev)

    pdf.build(story, onFirstPage=on_page, onLaterPages=on_page)
    buffer.seek(0)
    return buffer


# ============================================
# ENDPOINTS
# ============================================
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
        if not THREATFOX_KEY:
            return {
                "fuente": "ThreatFox",
                "encontrado": False,
                "status": "ok",
                "nota": "No disponible (API key no configurada)"
            }
        r = httpx.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": THREATFOX_KEY},
            json={"query": "search_ioc", "search_term": ioc_valor},
            timeout=10
        )
        d = r.json()
        if d.get("query_status") != "ok" or not d.get("data"):
            return {
                "fuente": "ThreatFox",
                "encontrado": False,
                "status": "ok",
                "nota": "No se encontraron IOCs asociados en la base de datos de malware conocido"
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
    except Exception as e:
        return {
            "fuente": "ThreatFox",
            "encontrado": False,
            "status": "ok",
            "nota": "No disponible en este momento"
        }


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
    inicio_hunt = datetime.now(timezone.utc)

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

    # 5. EVIDENCIAS DEL ULTIMO ANALISIS — para que el Hunter pueda citarlas
    evidencias = []
    mitre_previo = None
    fuentes_disponibles = {
        "virustotal": False, "abuseipdb": False, "threatfox": False,
        "urlscan": False, "mongo": len(historial) > 0
    }

    if historial:
        ultimo = historial[-1]
        mitre_previo = ultimo.get("mitre_tactica")
        evidencias.append(f"Score de riesgo: {ultimo.get('score', 0)}/100")
        if mitre_previo:
            evidencias.append(f"MITRE: {mitre_previo}")
        try:
            fuentes_ultimo = ultimo.get("fuentes")
            if isinstance(fuentes_ultimo, str):
                fuentes_ultimo = json.loads(fuentes_ultimo)
            for f in fuentes_ultimo or []:
                if f.get("fuente") == "VirusTotal" and f.get("status") == "ok":
                    fuentes_disponibles["virustotal"] = True
                    evidencias.append(
                        f"VirusTotal: {f.get('malicious', 0)} maliciosos de "
                        f"{f.get('malicious', 0) + f.get('suspicious', 0) + f.get('harmless', 0) + f.get('undetected', 0)} motores"
                    )
                if f.get("fuente") == "AbuseIPDB" and f.get("status") == "ok":
                    fuentes_disponibles["abuseipdb"] = True
                    evidencias.append(f"AbuseIPDB: {f.get('confidence_score', 0)}% confianza, {f.get('total_reports', 0)} reportes")
                if f.get("fuente") == "URLScan" and f.get("status") == "ok":
                    fuentes_disponibles["urlscan"] = True
        except Exception:
            pass

    fuentes_disponibles["threatfox"] = threatfox.get("status") == "ok" and threatfox.get("encontrado") is not None

    duracion_segundos = (datetime.now(timezone.utc) - inicio_hunt).total_seconds()

    return jsonify({
        "ioc": ioc,
        "correlacion_historica": correlacion_historica,
        "infraestructura_relacionada": infra_relacionada,
        "iocs_relacionados": iocs_relacionados,
        "threatfox": threatfox,
        "evidencias_analisis_previo": evidencias,
        "mitre_previo": mitre_previo,
        "fuentes_consultadas": fuentes_disponibles,
        "duracion_analisis_segundos": round(duracion_segundos, 2)
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

    # Traer correlacion SIEM mas reciente para este IOC, si existe
    siem_doc = db.siem_events.find_one({"ioc_principal": ioc}, {"_id": 0}, sort=[("created_at", -1)])
    if siem_doc:
        doc_data["correlacion_siem"] = siem_doc

    buffer = generar_pdf_informe(doc_data)
    filename = "ThreatOps_Informe_" + ioc.replace(".", "_") + ".pdf"
    return send_file(
        buffer, mimetype="application/pdf",
        as_attachment=True, download_name=filename
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
