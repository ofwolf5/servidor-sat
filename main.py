from fastapi import FastAPI, UploadFile, File, Form, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from typing import Optional, Dict, Any, List
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import base64
import zipfile
import io
import re
import uuid
import logging
import time
import asyncio

import pypdf

# Descarga masiva oficial de CFDI (SOAP)
from cfdiclient import (
    Fiel,
    Autenticacion,
    SolicitaDescargaEmitidos,
    SolicitaDescargaRecibidos,
    VerificaSolicitudDescarga,
    DescargaMasiva
)

# Autenticación HTTP directa para CSF y Opinión 32-D
from satcfdi.models import Signer
from satcfdi.portal import SATPortalConstancia, SATPortalOpinionCumplimiento

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sat_service")

app = FastAPI(
    title="Microservicio SAT Integral",
    description="Descarga Masiva CFDI, CSF, Opinión 32-D y Parser de Declaraciones Mensuales",
    version="7.5.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

TASKS: Dict[str, Dict[str, Any]] = {}

# ---------------------------------------------------------------------------
# Utilidades Criptográficas y Validación de Identidad
# ---------------------------------------------------------------------------

def parse_fecha(fecha_str: str, es_fin: bool = False) -> datetime:
    fecha_limpia = fecha_str.strip()
    if "T" in fecha_limpia:
        return datetime.fromisoformat(fecha_limpia)
    dt = datetime.strptime(fecha_limpia, "%Y-%m-%d")
    if es_fin:
        return dt.replace(hour=23, minute=59, second=59)
    return dt.replace(hour=0, minute=0, second=0)

def obtener_rfc_de_certificado(cer_bytes: bytes) -> str:
    """Extrae el RFC del Subject del certificado X.509."""
    try:
        cert = x509.load_der_x509_certificate(cer_bytes)
        for attr in cert.subject:
            if attr.oid._name in ("serialNumber", "x500UniqueIdentifier") or attr.oid.dotted_string == "2.5.4.5":
                val = attr.value.strip()
                if " " in val:
                    val = val.split(" ")[0]
                if "/" in val:
                    val = val.split("/")[0]
                return val.strip().upper()
    except Exception as e:
        logger.warning(f"No se pudo extraer RFC del certificado: {e}")
    return ""

def resolver_rfc(rfc_param: Optional[str], cer_bytes: bytes) -> str:
    rfc_certificado = obtener_rfc_de_certificado(cer_bytes)
    if rfc_certificado:
        return rfc_certificado
    if rfc_param and rfc_param.strip():
        return rfc_param.strip().upper()
    raise HTTPException(
        status_code=400,
        detail="No se pudo determinar el RFC a partir del certificado .cer."
    )

def cargar_fiel_cfdiclient(cer_bytes: bytes, key_bytes: bytes, password: str) -> Fiel:
    pwd_bytes = password.encode("utf-8") if isinstance(password, str) else password
    try:
        return Fiel(cer_bytes, key_bytes, password)
    except Exception:
        pass

    try:
        priv_key = serialization.load_der_private_key(key_bytes, password=pwd_bytes)
    except Exception:
        priv_key = serialization.load_pem_private_key(key_bytes, password=pwd_bytes)

    key_pkcs8_der = priv_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(pwd_bytes)
    )
    return Fiel(cer_bytes, key_pkcs8_der, password)

def obtener_token_fresco(fiel: Fiel) -> str:
    try:
        auth = Autenticacion(fiel)
        token = auth.obtener_token()
        if not token:
            raise Exception("El SAT no devolvió token.")
        return token
    except Exception as e:
        logger.error(f"Error obteniendo token SOAP SAT: {e}")
        raise HTTPException(
            status_code=401,
            detail=f"Falla de autenticación con el SAT (InvalidSecurity): {str(e)}"
        )

def extraer_xmls(paquete_data) -> list:
    if not paquete_data:
        return []

    if isinstance(paquete_data, str):
        try:
            paquete_bytes = base64.b64decode(paquete_data.strip())
        except Exception:
            paquete_bytes = paquete_data.encode("utf-8")
    elif isinstance(paquete_data, bytes):
        try:
            paquete_bytes = base64.b64decode(paquete_data)
        except Exception:
            paquete_bytes = paquete_data
    else:
        return []

    xmls = []
    try:
        with zipfile.ZipFile(io.BytesIO(paquete_bytes)) as z_padre:
            nombres = z_padre.namelist()
            for nombre in nombres:
                contenido = z_padre.read(nombre)
                if nombre.lower().endswith(".zip"):
                    try:
                        with zipfile.ZipFile(io.BytesIO(contenido)) as z_hijo:
                            for n2 in z_hijo.namelist():
                                if n2.lower().endswith(".xml"):
                                    xmls.append({
                                        "archivo": n2,
                                        "xml_contenido": z_hijo.read(n2).decode("utf-8", errors="ignore")
                                    })
                    except Exception as e_anidado:
                        logger.warning(f"Error en ZIP interno {nombre}: {e_anidado}")
                elif nombre.lower().endswith(".xml"):
                    xmls.append({
                        "archivo": nombre,
                        "xml_contenido": contenido.decode("utf-8", errors="ignore")
                    })
    except Exception as e:
        logger.error(f"Error procesando ZIP: {e}")

    return xmls

# ---------------------------------------------------------------------------
# Motor Parser de Declaraciones SAT (PDF)
# ---------------------------------------------------------------------------

def limpiar_monto_pdf(texto_monto: Optional[str]) -> float:
    if not texto_monto:
        return 0.0
    limpio = re.sub(r"[^\d.-]", "", texto_monto)
    try:
        return float(limpio) if limpio else 0.0
    except ValueError:
        return 0.0

def parsear_acuse_sat_bytes(pdf_bytes: bytes) -> Dict[str, Any]:
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    texto_paginas = []
    for pag in reader.pages:
        txt = pag.extract_text()
        if txt:
            texto_paginas.append(txt)
    texto = "\n".join(texto_paginas)
    
    lineas = [l.strip() for l in texto.split("\n") if l.strip()]
    texto_unificado = " ".join(lineas)

    # 1. Metadatos
    rfc_match = re.search(r"RFC:\s*([A-Z&Ñ]{3,4}\d{6}[A-V1-9][A-Z\d]{2})", texto, re.IGNORECASE)
    folio_match = re.search(r"(?:Número de operación|No\. de operación|Folio):\s*(\d{10,20})", texto, re.IGNORECASE)
    fecha_pres_match = re.search(r"Fecha y hora de presentación:\s*(\d{2}/\d{2}/\d{4}(?:\s+\d{2}:\d{2}(?::\d{2})?)?)", texto, re.IGNORECASE)
    ejercicio_match = re.search(r"Ejercicio:\s*(\d{4})", texto, re.IGNORECASE)
    periodo_match = re.search(r"Periodo:\s*([A-Za-z]+(?:\s*-\s*[A-Za-z]+)?)", texto, re.IGNORECASE)
    tipo_dec_match = re.search(r"Tipo de declaración:\s*([A-Za-z\s]+?)(?:\s{2,}|Fecha|Número|$)", texto, re.IGNORECASE)

    razon_social = ""
    rs_match = re.search(r"(?:Denominación o razón social|Nombre, denominación o razón social):\s*([^\n\r]+?)(?:\s{2,}|RFC:|$)", texto, re.IGNORECASE)
    if rs_match:
        razon_social = rs_match.group(1).strip()

    resultado: Dict[str, Any] = {
        "metadatos": {
            "rfc": rfc_match.group(1).upper() if rfc_match else "",
            "razon_social": razon_social,
            "ejercicio": int(ejercicio_match.group(1)) if ejercicio_match else None,
            "periodo": periodo_match.group(1).strip() if periodo_match else "",
            "tipo_declaracion": tipo_dec_match.group(1).strip() if tipo_dec_match else "Normal",
            "folio_operacion": folio_match.group(1) if folio_match else "",
            "fecha_presentacion": fecha_pres_match.group(1) if fecha_pres_match else "",
        },
        "iva": {
            "actos_gravados_16": 0.0,
            "actos_gravados_8": 0.0,
            "actos_gravados_0": 0.0,
            "actos_exentos": 0.0,
            "iva_trasladado_cobrado": 0.0,
            "iva_acreditable_pagado": 0.0,
            "retenciones_iva_que_le_efectuaron": 0.0,
            "iva_a_cargo": 0.0,
            "iva_a_favor": 0.0
        },
        "isr": {
            "ingresos_nominales": 0.0,
            "anticipos_clientes": 0.0,
            "total_ingresos_acumulables": 0.0,
            "isr_a_cargo": 0.0
        },
        "retenciones": {
            "sueldos_y_salarios": 0.0,
            "asimilados": 0.0,
            "servicios_profesionales": 0.0,
            "arrendamiento": 0.0,
            "fletes": 0.0,
            "resico_pf": 0.0,
            "retenciones_iva": 0.0,
            "otras_retenciones_isr": 0.0
        },
        "ieps": {
            "ieps_trasladado": 0.0,
            "ieps_acreditable": 0.0,
            "ieps_a_cargo": 0.0
        },
        "total_a_pagar": 0.0
    }

    # IVA
    m_iva_16 = re.search(r"(?:Total de actos o actividades gravados al 16%|Actividades gravadas al 16%)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_iva_16:
        resultado["iva"]["actos_gravados_16"] = limpiar_monto_pdf(m_iva_16.group(1))

    m_iva_tras = re.search(r"(?:IVA trasladado|Impuesto causado|Total del IVA causado)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_iva_tras:
        resultado["iva"]["iva_trasladado_cobrado"] = limpiar_monto_pdf(m_iva_tras.group(1))

    m_iva_acred = re.search(r"(?:Total del IVA acreditable|IVA acreditable del periodo|IVA acreditable)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_iva_acred:
        resultado["iva"]["iva_acreditable_pagado"] = limpiar_monto_pdf(m_iva_acred.group(1))

    m_iva_ret = re.search(r"(?:IVA que le retuvieron|Retenciones de IVA que le efectuaron)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_iva_ret:
        resultado["iva"]["retenciones_iva_que_le_efectuaron"] = limpiar_monto_pdf(m_iva_ret.group(1))

    m_iva_cargo = re.search(r"(?:Impuesto a cargo|Cantidad a cargo)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_iva_cargo:
        resultado["iva"]["iva_a_cargo"] = limpiar_monto_pdf(m_iva_cargo.group(1))

    m_iva_favor = re.search(r"(?:Saldo a favor|Cantidad a favor)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_iva_favor:
        resultado["iva"]["iva_a_favor"] = limpiar_monto_pdf(m_iva_favor.group(1))

    # ISR
    m_isr_ing = re.search(r"(?:Ingresos nominales del mes|Ingresos nominales|Total de ingresos facturados|Total de ingresos)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_isr_ing:
        resultado["isr"]["ingresos_nominales"] = limpiar_monto_pdf(m_isr_ing.group(1))

    m_isr_anticipos = re.search(r"(?:Anticipos de clientes recibidos|Anticipos de clientes)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_isr_anticipos:
        resultado["isr"]["anticipos_clientes"] = limpiar_monto_pdf(m_isr_anticipos.group(1))

    m_isr_tot_ing = re.search(r"(?:Total de ingresos acumulables|Ingresos acumulables)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_isr_tot_ing:
        resultado["isr"]["total_ingresos_acumulables"] = limpiar_monto_pdf(m_isr_tot_ing.group(1))

    m_isr_cargo = re.search(r"(?:ISR a cargo|Pago provisional de ISR a cargo)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_isr_cargo:
        resultado["isr"]["isr_a_cargo"] = limpiar_monto_pdf(m_isr_cargo.group(1))

    # Retenciones
    m_ret_sueldos = re.search(r"(?:Sueldos y salarios|Por sueldos y salarios)\s*.*?Monto retenido[:\s\$]*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if not m_ret_sueldos:
        m_ret_sueldos = re.search(r"(?:ISR retenciones por salarios|Retención por salarios)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_ret_sueldos:
        resultado["retenciones"]["sueldos_y_salarios"] = limpiar_monto_pdf(m_ret_sueldos.group(1))

    m_ret_asimilados = re.search(r"(?:Asimilados a salarios|Por asimilados a salarios)\s*.*?Monto retenido[:\s\$]*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_ret_asimilados:
        resultado["retenciones"]["asimilados"] = limpiar_monto_pdf(m_ret_asimilados.group(1))

    m_ret_hon = re.search(r"(?:Servicios profesionales|Por servicios profesionales)\s*.*?Monto retenido[:\s\$]*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_ret_hon:
        resultado["retenciones"]["servicios_profesionales"] = limpiar_monto_pdf(m_ret_hon.group(1))

    m_ret_arr = re.search(r"(?:Arrendamiento de inmuebles|Por uso o goce temporal de bienes|Arrendamiento)\s*.*?Monto retenido[:\s\$]*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_ret_arr:
        resultado["retenciones"]["arrendamiento"] = limpiar_monto_pdf(m_ret_arr.group(1))

    m_ret_fletes = re.search(r"(?:Autotransporte terrestre de carga|Fletes|Servicios de autotransporte)\s*.*?Monto retenido[:\s\$]*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_ret_fletes:
        resultado["retenciones"]["fletes"] = limpiar_monto_pdf(m_ret_fletes.group(1))

    m_ret_resico = re.search(r"(?:Régimen simplificado de confianza|RESICO)\s*.*?Monto retenido[:\s\$]*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_ret_resico:
        resultado["retenciones"]["resico_pf"] = limpiar_monto_pdf(m_ret_resico.group(1))

    m_ret_iva_tot = re.search(r"(?:Retenciones de IVA|Total de retenciones de IVA)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_ret_iva_tot:
        resultado["retenciones"]["retenciones_iva"] = limpiar_monto_pdf(m_ret_iva_tot.group(1))

    # IEPS y Total
    m_ieps_tras = re.search(r"(?:IEPS causado|IEPS trasladado)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_ieps_tras:
        resultado["ieps"]["ieps_trasladado"] = limpiar_monto_pdf(m_ieps_tras.group(1))

    m_ieps_acred = re.search(r"(?:IEPS acreditable)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_ieps_acred:
        resultado["ieps"]["ieps_acreditable"] = limpiar_monto_pdf(m_ieps_acred.group(1))

    m_total_pagar = re.search(r"(?:Total a pagar|Cantidad a pagar|Línea de captura.*?Importe a pagar)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_total_pagar:
        resultado["total_a_pagar"] = limpiar_monto_pdf(m_total_pagar.group(1))

    return resultado

# ---------------------------------------------------------------------------
# Workers en Segundo Plano: CSF y Opinión 32-D (satcfdi)
# ---------------------------------------------------------------------------

def _generar_csf_sync(cer_bytes: bytes, key_bytes: bytes, password: str) -> bytes:
    signer = Signer.load(certificate=cer_bytes, key=key_bytes, password=password)
    sp = SATPortalConstancia(signer)
    return sp.generar_constancia()

async def tarea_descargar_csf(task_id: str, cer_bytes: bytes, key_bytes: bytes, password: str, rfc: str):
    TASKS[task_id] = {"status": "processing", "tipo": "csf", "created_at": datetime.now().isoformat()}
    try:
        pdf_bytes = await asyncio.to_thread(_generar_csf_sync, cer_bytes, key_bytes, password)

        reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
        texto = "".join([pg.extract_text() or "" for pg in reader.pages])

        cp_match = re.search(r"Código Postal:?\s*(\d{5})", texto, re.IGNORECASE)
        codigo_postal = cp_match.group(1) if cp_match else ""

        pdf_b64 = base64.b64encode(pdf_bytes).decode("utf-8")

        TASKS[task_id] = {
            "status": "completed",
            "rfc": rfc,
            "codigo_postal": codigo_postal,
            "pdf_base64": pdf_b64,
            "fecha_emision": datetime.now().isoformat()
        }
        logger.info(f"CSF descargada con éxito para {rfc}.")
    except Exception as e:
        logger.error(f"Error generando CSF para {rfc}: {e}")
        TASKS[task_id] = {
            "status": "failed",
            "error": f"Falla en el portal del SAT: {str(e)}"
        }

def _generar_opinion_sync(cer_bytes: bytes, key_bytes: bytes, password: str) -> bytes:
    signer = Signer.load(certificate=cer_bytes, key=key_bytes, password=password)
    ultimo_error = None
    for intento in range(1, 4):
        try:
            logger.info(f"Consultando Opinión 32-D vía satcfdi (Intento {intento}/3)...")
            op = SATPortalOpinionCumplimiento(signer)
            op.headers.update({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
            })
            pdf_bytes = op.generar_opinion_cumplimiento()
            if pdf_bytes and len(pdf_bytes) > 500:
                return pdf_bytes
        except Exception as e:
            ultimo_error = e
            logger.warning(f"Intento {intento} falló para Opinión 32-D: {e}")
            time.sleep(5)

    raise ultimo_error

async def tarea_descargar_opinion(task_id: str, cer_bytes: bytes, key_bytes: bytes, password: str, rfc: str):
    TASKS[task_id] = {"status": "processing", "tipo": "opinion", "created_at": datetime.now().isoformat()}
    try:
        pdf_bytes = await asyncio.to_thread(_generar_opinion_sync, cer_bytes, key_bytes, password)

        reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
        texto_completo = "".join([pg.extract_text() or "" for pg in reader.pages]).upper()

        if "POSITIVO" in texto_completo:
            opinion_status = "POSITIVA"
        elif "NEGATIVO" in texto_completo:
            opinion_status = "NEGATIVA"
        elif "NO INSCRITO" in texto_completo or "SIN OBLIGACIONES" in texto_completo:
            opinion_status = "SIN_OPINION"
        else:
            opinion_status = "REVISION"

        pdf_b64 = base64.b64encode(pdf_bytes).decode("utf-8")

        TASKS[task_id] = {
            "status": "completed",
            "rfc": rfc,
            "opinion_status": opinion_status,
            "pdf_base64": pdf_b64,
            "fecha_consulta": datetime.now().isoformat()
        }
        logger.info(f"Opinión 32-D generada con éxito ({opinion_status}) para {rfc}.")
    except Exception as e:
        logger.error(f"Error generando Opinión 32-D para {rfc}: {e}")
        TASKS[task_id] = {
            "status": "failed",
            "error": f"Falla en el portal del SAT: {str(e)}"
        }

# ---------------------------------------------------------------------------
# Endpoints de Salud y Polling
# ---------------------------------------------------------------------------

@app.get("/")
def ruta_raiz():
    return {
        "status": "ok",
        "servicio": "SAT Descarga Masiva, CSF, Opinión 32-D y Conciliación API",
        "version": "7.5.0"
    }

@app.get("/health")
def health_check():
    return {"status": "healthy", "version": "7.5.0"}

@app.get("/api/sat/task-status/{task_id}")
def obtener_estado_tarea(task_id: str):
    if task_id not in TASKS:
        raise HTTPException(status_code=404, detail="Tarea no encontrada o expirada.")
    return TASKS[task_id]

# ---------------------------------------------------------------------------
# Endpoints de CSF, Opinión 32-D y Parseo de Declaración
# ---------------------------------------------------------------------------

@app.post("/api/sat/parse-declaracion")
async def parse_declaracion_endpoint(archivo_acuse: UploadFile = File(...)):
    """
    Recibe el PDF del acuse de la declaración mensual del SAT y devuelve
    el JSON desglosado con todos los renglones fiscales declarados.
    """
    if not archivo_acuse.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="El archivo proporcionado debe ser un documento PDF.")

    contenido_pdf = await archivo_acuse.read()
    if len(contenido_pdf) == 0:
        raise HTTPException(status_code=400, detail="El archivo PDF está vacío.")

    try:
        datos_declaracion = parsear_acuse_sat_bytes(contenido_pdf)
        return {
            "status": "success",
            "archivo": archivo_acuse.filename,
            "datos": datos_declaracion
        }
    except Exception as e:
        logger.error(f"Error parseando acuse SAT: {e}")
        raise HTTPException(status_code=500, detail=f"No se pudo interpretar el acuse del SAT: {str(e)}")

@app.post("/api/sat/sync-csf")
async def iniciar_sync_csf(
    background_tasks: BackgroundTasks,
    cer_file: UploadFile = File(...),
    key_file: UploadFile = File(...),
    password: str = Form(...),
    rfc: Optional[str] = Form(None)
):
    cer_bytes = await cer_file.read()
    key_bytes = await key_file.read()
    rfc_contribuyente = resolver_rfc(rfc, cer_bytes)

    task_id = str(uuid.uuid4())
    TASKS[task_id] = {"status": "processing", "tipo": "csf"}

    background_tasks.add_task(
        tarea_descargar_csf,
        task_id=task_id,
        cer_bytes=cer_bytes,
        key_bytes=key_bytes,
        password=password,
        rfc=rfc_contribuyente
    )

    return {
        "status": "processing",
        "task_id": task_id,
        "message": "Generación de CSF iniciada en segundo plano."
    }

@app.post("/api/sat/sync-opinion")
async def iniciar_sync_opinion(
    background_tasks: BackgroundTasks,
    cer_file: UploadFile = File(...),
    key_file: UploadFile = File(...),
    password: str = Form(...),
    rfc: Optional[str] = Form(None)
):
    cer_bytes = await cer_file.read()
    key_bytes = await key_file.read()
    rfc_contribuyente = resolver_rfc(rfc, cer_bytes)

    task_id = str(uuid.uuid4())
    TASKS[task_id] = {"status": "processing", "tipo": "opinion"}

    background_tasks.add_task(
        tarea_descargar_opinion,
        task_id=task_id,
        cer_bytes=cer_bytes,
        key_bytes=key_bytes,
        password=password,
        rfc=rfc_contribuyente
    )

    return {
        "status": "processing",
        "task_id": task_id,
        "message": "Consulta de Opinión 32-D iniciada en segundo plano."
    }

# ---------------------------------------------------------------------------
# CFDI Descarga Masiva (SOAP Oficial)
# ---------------------------------------------------------------------------

@app.post("/api/sat/solicitar")
async def solicitar_descarga(
    cer_file: UploadFile = File(...),
    key_file: UploadFile = File(...),
    password: str = Form(...),
    rfc: str = Form(...),
    fecha_inicio: str = Form(...),
    fecha_fin: str = Form(...),
    tipo: str = Form(...)
):
    cer_bytes = await cer_file.read()
    key_bytes = await key_file.read()

    rfc_firmante = resolver_rfc(rfc, cer_bytes)
    fiel = cargar_fiel_cfdiclient(cer_bytes, key_bytes, password)
    token = obtener_token_fresco(fiel)

    f_inicio_dt = parse_fecha(fecha_inicio, es_fin=False)
    f_fin_dt = parse_fecha(fecha_fin, es_fin=True)
    es_emitidos = tipo.lower().strip() == "emitidos"

    logger.info(f"Enviando solicitud SOAP al SAT ({tipo}) para RFC {rfc_firmante} [{f_inicio_dt} -> {f_fin_dt}]")

    try:
        if es_emitidos:
            descarga = SolicitaDescargaEmitidos(fiel)
            res = descarga.solicitar_descarga(
                token=token,
                rfc_solicitante=rfc_firmante,
                fecha_inicial=f_inicio_dt,
                fecha_final=f_fin_dt,
                rfc_emisor=rfc_firmante,
                tipo_solicitud="CFDI"
            )
        else:
            descarga = SolicitaDescargaRecibidos(fiel)
            res = descarga.solicitar_descarga(
                token=token,
                rfc_solicitante=rfc_firmante,
                fecha_inicial=f_inicio_dt,
                fecha_final=f_fin_dt,
                rfc_receptor=rfc_firmante,
                tipo_solicitud="CFDI"
            )

        cod_estatus = str(res.get("cod_estatus", res.get("CodEstatus", "5000")))
        mensaje = res.get("mensaje", res.get("Mensaje", "Solicitud aceptada"))

        logger.info(f"Respuesta SAT Solicitar: Codigo {cod_estatus} - {mensaje}")

        if cod_estatus != "5000":
            raise HTTPException(
                status_code=400,
                detail=f"SAT Código {cod_estatus}: {mensaje}"
            )

        id_solicitud = res.get("id_solicitud", res.get("IdSolicitud"))
        return {
            "status": "success",
            "id_solicitud": id_solicitud,
            "codigo_estatus": cod_estatus,
            "mensaje": mensaje
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en solicitud SAT: {e}")
        raise HTTPException(status_code=502, detail=f"Error en Web Service SAT: {str(e)}")

@app.post("/api/sat/verificar")
async def verificar_solicitud(
    cer_file: UploadFile = File(...),
    key_file: UploadFile = File(...),
    password: str = Form(...),
    id_solicitud: str = Form(...),
    rfc: Optional[str] = Form(None)
):
    cer_bytes = await cer_file.read()
    key_bytes = await key_file.read()

    rfc_firmante = resolver_rfc(rfc, cer_bytes)
    fiel = cargar_fiel_cfdiclient(cer_bytes, key_bytes, password)
    token = obtener_token_fresco(fiel)

    try:
        verificador = VerificaSolicitudDescarga(fiel)
        res = verificador.verificar_descarga(
            token=token,
            rfc_solicitante=rfc_firmante,
            id_solicitud=id_solicitud.strip()
        )

        paquetes = res.get("paquetes", res.get("IdsPaquetes", []))
        estado = str(res.get("estado_solicitud", res.get("EstadoSolicitud", "2")))
        numero_cfdis = int(res.get("numero_cfdis", res.get("NumeroCFDIs", len(paquetes))))

        return {
            "id_solicitud": id_solicitud,
            "estado_solicitud": estado,
            "codigo_estado_solicitud": str(res.get("codigo_estado_solicitud", "5000")),
            "numero_cfdis": numero_cfdis,
            "paquetes_listos": len(paquetes) > 0 and estado == "3",
            "ids_paquetes": paquetes
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error verificando solicitud: {e}")
        raise HTTPException(status_code=502, detail=f"Error consultando al SAT: {str(e)}")

@app.post("/api/sat/descargar-paquete")
async def descargar_paquete(
    cer_file: UploadFile = File(...),
    key_file: UploadFile = File(...),
    password: str = Form(...),
    id_paquete: str = Form(...),
    rfc: Optional[str] = Form(None)
):
    cer_bytes = await cer_file.read()
    key_bytes = await key_file.read()

    rfc_firmante = resolver_rfc(rfc, cer_bytes)
    fiel = cargar_fiel_cfdiclient(cer_bytes, key_bytes, password)
    token = obtener_token_fresco(fiel)

    try:
        descargador = DescargaMasiva(fiel)
        res = descargador.descargar_paquete(
            token=token,
            rfc_solicitante=rfc_firmante,
            id_paquete=id_paquete.strip()
        )

        paquete_b64 = res.get("paquete_b64", res.get("PaqueteB64", res.get("paquete")))
        if not paquete_b64:
            raise HTTPException(status_code=404, detail="El SAT no devolvió contenido para este paquete.")

        xmls = extraer_xmls(paquete_b64)
        if not xmls:
            raise HTTPException(
                status_code=500,
                detail=f"El paquete {id_paquete} no contenía archivos XML legibles."
            )

        return {
            "id_paquete": id_paquete,
            "total_xmls": len(xmls),
            "comprobantes": xmls
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error descargando paquete: {e}")
        raise HTTPException(status_code=502, detail=f"Error al descargar del SAT: {str(e)}")
