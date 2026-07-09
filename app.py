from flask import Flask, request, jsonify, send_file
from pymongo import MongoClient
import httpx
import json
import os
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


# ============================================
# CONFIGURACIÓN — todo desde variables de entorno
# ============================================
MONGODB_URI = os.environ.get("MONGODB_URI", "")
VT_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
ABUSE_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
IPINFO_KEY = os.environ.get("IPINFO_TOKEN", "")

client_mongo = MongoClient(MONGODB_URI)
db = client_mongo.threatops


# ============================================
# ENRIQUECIMIENTO — 3 APIs en paralelo
# ============================================
def enriquecer_sync(ioc):

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

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        future_vt = executor.submit(get_vt)
        future_abuse = executor.submit(get_abuse)
        future_ipinfo = executor.submit(get_ipinfo)

        vt = future_vt.result()
        abuse = future_abuse.result()
        ipinfo = future_ipinfo.result()

    score = 0
    if vt.get("status") == "ok":
        score += vt["malicious"] * 2
    if abuse.get("status") == "ok":
        score += abuse["confidence_score"] * 0.5
    score = min(round(score), 100)

    return {"fuentes": [vt, abuse, ipinfo], "score": score}


# ============================================
# GENERADOR DE PDF — nivel ingeniería
# ============================================
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

    enriquecido = enriquecer_sync(ioc)

    return jsonify({
        "ioc": ioc,
        "resultado": enriquecido
    })


@app.route("/iocs")
def get_iocs():
    iocs = list(db.iocs.find({}, {"_id": 0}))
    return jsonify({"total": len(iocs), "iocs": iocs})


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
