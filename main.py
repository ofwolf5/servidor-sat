from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from typing import Optional
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import base64
import zipfile
import io
import os
import re
import tempfile
import logging

from playwright.async_api import async_playwright
import pypdf

from cfdiclient import (
    Fiel,
    Autenticacion,
    SolicitaDescargaEmitidos,
    SolicitaDescargaRecibidos,
    VerificaSolicitudDescarga,
    DescargaMasiva
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sat_service")

app = FastAPI(
    title="Microservicio SAT Integral",
    description="Descarga Masiva CFDI, CSF y Opinión de Cumplimiento 32-D",
    version="6.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

CHROME_ARGS = [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--disable-blink-features=AutomationControlled"
]

# ---------------------------------------------------------------------------
# Utilidades Criptográficas y CFDIClient
# ---------------------------------------------------------------------------

def parse_fecha(fecha_str: str, es_fin: bool = False) -> datetime:
    fecha_limpia = fecha_str.strip()
    if "T" in fecha_limpia:
        return datetime.fromisoformat(fecha_limpia)
    dt = datetime.strptime(fecha_limpia, "%Y-%m-%d")
    if es_fin:
        return dt.replace(hour=23, minute=59, second=59)
    return dt.replace(hour=0, minute=0, second=0)

def normalizar_llave_privada(key_bytes: bytes, password: str) -> bytes:
    pwd_bytes = password.encode("utf-8") if isinstance(password, str) else password
    try:
        priv_key = serialization.load_der_private_key(key_bytes, password=pwd_bytes)
    except Exception:
        try:
            priv_key = serialization.load_pem_private_key(key_bytes, password=pwd_bytes)
        except Exception as e_pem:
            logger.error(f"Falla al descifrar la llave privada con la contraseña: {e_pem}")
            raise HTTPException(
                status_code=400,
                detail=f"No se pudo descifrar el archivo .key. Verifique su contraseña: {str(e_pem)}"
            )

    return priv_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(pwd_bytes)
    )

def cargar_fiel(cer_bytes: bytes, key_bytes: bytes, password: str) -> Fiel:
    try:
        return Fiel(cer_bytes, key_bytes, password)
    except Exception:
        key_normalizada = normalizar_llave_privada(key_bytes, password)
        return Fiel(cer_bytes, key_normalizada, password)

def obtener_rfc_de_certificado(cer_bytes: bytes) -> str:
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
    if rfc_param and rfc_param.strip():
        return rfc_param.strip().upper()
    rfc_extraido = obtener_rfc_de_certificado(cer_bytes)
    if rfc_extraido:
        return rfc_extraido
    raise HTTPException(
        status_code=400,
        detail="No se pudo determinar el RFC. Envíe el RFC en el formulario o verifique el .cer."
    )

def obtener_token_fresco(fiel: Fiel) -> str:
    try:
        auth = Autenticacion(fiel)
        token = auth.obtener_token()
        if not token:
            raise Exception("El SAT no devolvió token.")
        return token
    except Exception as e:
        logger.error(f"Error obteniendo token SAT: {e}")
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
# Automatización Portal SAT (Playwright)
# ---------------------------------------------------------------------------

async def autenticar_portal_sat(page, cer_path: str, key_path: str, password: str):
    """Realiza el login interactivo por e.firma en el SSO del SAT."""
    try:
        btn_efirma = page.locator("#buttonFiel, a[href*='fiel'], button:has-text('e.firma')").first
        if await btn_efirma.is_visible(timeout=4000):
            await btn_efirma.click()

        await page.wait_for_selector("input[type='file']", timeout=20000)
        
        file_inputs = await page.locator("input[type='file']").all()
        if len(file_inputs) >= 2:
            await file_inputs[0].set_input_files(cer_path)
            await file_inputs[1].set_input_files(key_path)
        else:
            await page.set_input_files("input#fileCertificate, input[name*='cert']", cer_path)
            await page.set_input_files("input#filePrivateKey, input[name*='key']", key_path)

        await page.fill("input#privateKeyPassword, input#txtPassword, input[type='password']", password)

        btn_submit = page.locator("input#submit, button#submit, input[type='submit'], button:has-text('Enviar')").first
        await btn_submit.click()
        await page.wait_for_load_state("networkidle", timeout=30000)
    except Exception as e:
        logger.error(f"Falla durante la autenticación e.firma: {e}")
        raise HTTPException(status_code=401, detail=f"No se pudo completar el acceso con e.firma al SAT: {str(e)}")

# ---------------------------------------------------------------------------
# Endpoints Base y CFDI Descarga Masiva
# ---------------------------------------------------------------------------

@app.get("/")
def ruta_raiz():
    return {
        "status": "ok",
        "servicio": "SAT Descarga Masiva, CSF y Opinión 32-D API",
        "motor": "cfdiclient + playwright",
        "version": "6.1.0"
    }

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

    fiel = cargar_fiel(cer_bytes, key_bytes, password)
    token = obtener_token_fresco(fiel)

    f_inicio_dt = parse_fecha(fecha_inicio, es_fin=False)
    f_fin_dt = parse_fecha(fecha_fin, es_fin=True)
    rfc_solicitante = resolver_rfc(rfc, cer_bytes)
    es_emitidos = tipo.lower() == "emitidos"

    logger.info(f"Solicitando {tipo} para RFC {rfc_solicitante} ({f_inicio_dt} a {f_fin_dt})")

    try:
        if es_emitidos:
            descarga = SolicitaDescargaEmitidos(fiel)
            res = descarga.solicitar_descarga(
                token=token,
                rfc_solicitante=rfc_solicitante,
                fecha_inicial=f_inicio_dt,
                fecha_final=f_fin_dt,
                rfc_emisor=rfc_solicitante,
                tipo_solicitud="CFDI"
            )
        else:
            descarga = SolicitaDescargaRecibidos(fiel)
            res = descarga.solicitar_descarga(
                token=token,
                rfc_solicitante=rfc_solicitante,
                fecha_inicial=f_inicio_dt,
                fecha_final=f_fin_dt,
                rfc_receptor=rfc_solicitante,
                tipo_solicitud="CFDI"
            )

        cod_estatus = str(res.get("cod_estatus", res.get("CodEstatus", "5000")))
        mensaje = res.get("mensaje", res.get("Mensaje", "Solicitud aceptada"))

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

    fiel = cargar_fiel(cer_bytes, key_bytes, password)
    token = obtener_token_fresco(fiel)
    rfc_solicitante = resolver_rfc(rfc, cer_bytes)

    try:
        verificador = VerificaSolicitudDescarga(fiel)
        res = verificador.verificar_descarga(
            token=token,
            rfc_solicitante=rfc_solicitante,
            id_solicitud=id_solicitud
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

    fiel = cargar_fiel(cer_bytes, key_bytes, password)
    token = obtener_token_fresco(fiel)
    rfc_solicitante = resolver_rfc(rfc, cer_bytes)

    try:
        descargador = DescargaMasiva(fiel)
        res = descargador.descargar_paquete(
            token=token,
            rfc_solicitante=rfc_solicitante,
            id_paquete=id_paquete
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

# ---------------------------------------------------------------------------
# Módulos: Opinión 32-D y Constancia de Situación Fiscal (CSF)
# ---------------------------------------------------------------------------

@app.post("/api/sat/sync-opinion")
async def obtener_opinion_cumplimiento(
    cer_file: UploadFile = File(...),
    key_file: UploadFile = File(...),
    password: str = Form(...),
    rfc: Optional[str] = Form(None)
):
    """Consulta y descarga la Opinión del Cumplimiento (32-D) en PDF y determina su estatus."""
    cer_bytes = await cer_file.read()
    key_bytes = await key_file.read()
    rfc_contribuyente = resolver_rfc(rfc, cer_bytes)

    with tempfile.TemporaryDirectory() as temp_dir:
        cer_path = os.path.join(temp_dir, "fiel.cer")
        key_path = os.path.join(temp_dir, "fiel.key")

        with open(cer_path, "wb") as f_cer, open(key_path, "wb") as f_key:
            f_cer.write(cer_bytes)
            f_key.write(key_bytes)

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, args=CHROME_ARGS)
            context = await browser.new_context(
                accept_downloads=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
            )
            page = await context.new_page()

            try:
                # URL oficial de acceso a Opinión de Cumplimiento
                url_opinion = "https://ptscconsulta.sat.gob.mx/OpinionCumplimiento/"
                await page.goto(url_opinion, wait_until="domcontentloaded", timeout=60000)

                # Si pide autenticación por e.firma
                if "login" in page.url.lower() or "nidp" in page.url.lower() or "acceso" in page.url.lower():
                    await autenticar_portal_sat(page, cer_path, key_path, password)

                await page.wait_for_load_state("networkidle", timeout=45000)

                async with page.expect_download(timeout=60000) as download_info:
                    btn_descarga = page.locator("a[id*='descargar'], button[id*='descargar'], input[value*='Descargar'], a:has-text('Descargar'), button:has-text('Descargar')").first
                    if await btn_descarga.is_visible():
                        await btn_descarga.click()

                download = await download_info.value
                pdf_path = os.path.join(temp_dir, "opinion_32d.pdf")
                await download.save_as(pdf_path)

                with open(pdf_path, "rb") as pdf_file:
                    pdf_bytes = pdf_file.read()

                reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
                texto_completo = "".join([pg.extract_text() or "" for pg in reader.pages]).upper()

                if "POSITIVO" in texto_completo:
                    status = "POSITIVA"
                elif "NEGATIVO" in texto_completo:
                    status = "NEGATIVA"
                elif "NO INSCRITO" in texto_completo or "SIN OBLIGACIONES" in texto_completo:
                    status = "SIN_OPINION"
                else:
                    status = "REVISION"

                pdf_b64 = base64.b64encode(pdf_bytes).decode("utf-8")

                return {
                    "status": "success",
                    "rfc": rfc_contribuyente,
                    "opinion_status": status,
                    "pdf_base64": pdf_b64,
                    "fecha_consulta": datetime.now().isoformat()
                }

            except Exception as e:
                logger.error(f"Error consultando 32-D: {e}")
                raise HTTPException(status_code=502, detail=f"Falla al generar Opinión de Cumplimiento: {str(e)}")
            finally:
                await browser.close()

@app.post("/api/sat/sync-csf")
async def obtener_csf(
    cer_file: UploadFile = File(...),
    key_file: UploadFile = File(...),
    password: str = Form(...),
    rfc: Optional[str] = Form(None)
):
    """Genera la Constancia de Situación Fiscal (CSF), extrae los datos clave y devuelve el PDF."""
    cer_bytes = await cer_file.read()
    key_bytes = await key_file.read()
    rfc_contribuyente = resolver_rfc(rfc, cer_bytes)

    with tempfile.TemporaryDirectory() as temp_dir:
        cer_path = os.path.join(temp_dir, "fiel.cer")
        key_path = os.path.join(temp_dir, "fiel.key")

        with open(cer_path, "wb") as f_cer, open(key_path, "wb") as f_key:
            f_cer.write(cer_bytes)
            f_key.write(key_bytes)

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, args=CHROME_ARGS)
            context = await browser.new_context(
                accept_downloads=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
            )
            page = await context.new_page()

            try:
                # URL de reimpresión de acuses / CIF
                url_cif = "https://ptscdecypag.sat.gob.mx/ReimpresionAcuses/"
                await page.goto(url_cif, wait_until="domcontentloaded", timeout=60000)

                if "login" in page.url.lower() or "nidp" in page.url.lower() or "acceso" in page.url.lower():
                    await autenticar_portal_sat(page, cer_path, key_path, password)

                await page.wait_for_load_state("networkidle", timeout=30000)

                # Localizar el botón 'Generar Constancia' en página o frames
                btn_generar = page.locator("button:has-text('Generar Constancia'), input[value*='Generar Constancia'], a:has-text('Generar Constancia')").first

                if not await btn_generar.is_visible():
                    for frame in page.frames:
                        frame_btn = frame.locator("button:has-text('Generar Constancia'), input[value*='Generar Constancia']").first
                        if await frame_btn.is_visible():
                            btn_generar = frame_btn
                            break

                await btn_generar.wait_for(state="visible", timeout=45000)

                async with page.expect_download(timeout=45000) as download_info:
                    await btn_generar.click()

                download = await download_info.value
                pdf_path = os.path.join(temp_dir, "csf.pdf")
                await download.save_as(pdf_path)

                with open(pdf_path, "rb") as f_pdf:
                    pdf_bytes = f_pdf.read()

                reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
                texto = "".join([pg.extract_text() or "" for pg in reader.pages])

                cp_match = re.search(r"Código Postal:?\s*(\d{5})", texto, re.IGNORECASE)
                codigo_postal = cp_match.group(1) if cp_match else ""

                pdf_b64 = base64.b64encode(pdf_bytes).decode("utf-8")

                return {
                    "status": "success",
                    "rfc": rfc_contribuyente,
                    "codigo_postal": codigo_postal,
                    "pdf_base64": pdf_b64,
                    "fecha_emision": datetime.now().isoformat()
                }

            except Exception as e:
                logger.error(f"Error generando CSF: {e}")
                raise HTTPException(status_code=502, detail=f"Falla al generar CSF: {str(e)}")
            finally:
                await browser.close()
