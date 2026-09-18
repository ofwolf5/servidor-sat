from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import base64
import zipfile
import io
import logging

# Clases oficiales de cfdiclient 1.6.3
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
    title="Microservicio de Descarga Masiva SAT",
    description="Backend oficial cfdiclient para Lovable",
    version="5.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def parse_fecha(fecha_str: str, es_fin: bool = False) -> datetime:
    """Convierte cadenas YYYY-MM-DD a objetos datetime requeridos por cfdiclient."""
    fecha_limpia = fecha_str.strip()
    if "T" in fecha_limpia:
        return datetime.fromisoformat(fecha_limpia)
    dt = datetime.strptime(fecha_limpia, "%Y-%m-%d")
    if es_fin:
        return dt.replace(hour=23, minute=59, second=59)
    return dt.replace(hour=0, minute=0, second=0)

def cargar_fiel(cer_bytes: bytes, key_bytes: bytes, password: str) -> Fiel:
    """Inicializa la FIEL con cfdiclient (argumentos posicionales)."""
    try:
        return Fiel(cer_bytes, key_bytes, password)
    except Exception as e:
        logger.error(f"Error cargando Fiel: {e}")
        raise HTTPException(
            status_code=400,
            detail=f"Error al validar e.firma o contraseña: {str(e)}"
        )

def obtener_token_fresco(fiel: Fiel) -> str:
    """Genera un token nuevo en cada llamada para evitar expiración (5 min)."""
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
    """Decodifica Base64 y extrae XMLs directos o anidados en .zip."""
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
            logger.info(f"Nombres en el ZIP del SAT ({len(nombres)} archivos): {nombres[:10]}")
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
        logger.error(f"Error leyendo ZIP: {e}")

    logger.info(f"Total XMLs extraídos: {len(xmls)}")
    return xmls

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/")
def ruta_raiz():
    return {
        "status": "ok",
        "servicio": "SAT Descarga Masiva API",
        "motor": "cfdiclient-oficial",
        "version": "5.0.0"
    }

@app.post("/api/sat/solicitar")
async def solicitar_descarga(
    cer_file: UploadFile = File(...),
    key_file: UploadFile = File(...),
    password: str = Form(...),
    rfc: str = Form(...),
    fecha_inicio: str = Form(...),
    fecha_fin: str = Form(...),
    tipo: str = Form(...)  # "emitidos" o "recibidos"
):
    cer_bytes = await cer_file.read()
    key_bytes = await key_file.read()

    fiel = cargar_fiel(cer_bytes, key_bytes, password)
    token = obtener_token_fresco(fiel)

    f_inicio_dt = parse_fecha(fecha_inicio, es_fin=False)
    f_fin_dt = parse_fecha(fecha_fin, es_fin=True)
    rfc_limpio = rfc.strip().upper()
    es_emitidos = tipo.lower() == "emitidos"

    logger.info(f"Solicitando {tipo} para RFC {rfc_limpio} de {f_inicio_dt} a {f_fin_dt}")

    try:
        if es_emitidos:
            descarga = SolicitaDescargaEmitidos(fiel)
            res = descarga.solicitar_descarga(
                token=token,
                rfc_solicitante=rfc_limpio,
                fecha_inicial=f_inicio_dt,
                fecha_final=f_fin_dt,
                rfc_emisor=rfc_limpio,
                tipo_solicitud="CFDI"
            )
        else:
            descarga = SolicitaDescargaRecibidos(fiel)
            res = descarga.solicitar_descarga(
                token=token,
                rfc_solicitante=rfc_limpio,
                fecha_inicial=f_inicio_dt,
                fecha_final=f_fin_dt,
                rfc_receptor=rfc_limpio,
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
    id_solicitud: str = Form(...)
):
    cer_bytes = await cer_file.read()
    key_bytes = await key_file.read()

    fiel = cargar_fiel(cer_bytes, key_bytes, password)
    token = obtener_token_fresco(fiel)

    try:
        verificador = VerificaSolicitudDescarga(fiel)
        res = verificador.verificar_descarga(
            token=token,
            rfc_solicitante=fiel.rfc,
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
    id_paquete: str = Form(...)
):
    cer_bytes = await cer_file.read()
    key_bytes = await key_file.read()

    fiel = cargar_fiel(cer_bytes, key_bytes, password)
    token = obtener_token_fresco(fiel)

    try:
        descargador = DescargaMasiva(fiel)
        res = descargador.descargar_paquete(
            token=token,
            rfc_solicitante=fiel.rfc,
            id_paquete=id_paquete
        )

        paquete_b64 = res.get("paquete_b64", res.get("PaqueteB64", res.get("paquete")))
        if not paquete_b64:
            raise HTTPException(status_code=404, detail="El SAT no devolvió contenido para este paquete.")

        xmls = extraer_xmls(paquete_b64)
        if not xmls:
            raise HTTPException(
                status_code=500,
                detail=f"El paquete {id_paquete} fue entregado por el SAT pero no contenía archivos XML legibles."
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
