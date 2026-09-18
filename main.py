from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import base64
import zipfile
import io
import logging

# Clases oficiales de cfdiclient para el Web Service SOAP del SAT
from cfdiclient import (
    Fiel,
    Autenticacion,
    SolicitaDescarga,
    VerificaSolicitudDescarga,
    DescargaMasiva
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sat_service")

app = FastAPI(
    title="Microservicio de Descarga Masiva SAT",
    description="Backend puente con cfdiclient para Lovable",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def formatear_fecha_sat(fecha_str: str, es_fin: bool = False) -> str:
    """Asegura formato estricto ISO YYYY-MM-DDTHH:MM:SS requerido por el SAT."""
    fecha_limpia = fecha_str.strip()
    if "T" not in fecha_limpia:
        hora = "23:59:59" if es_fin else "00:00:00"
        return f"{fecha_limpia}T{hora}"
    return fecha_limpia

def cargar_fiel(cer_bytes: bytes, key_bytes: bytes, password: str) -> Fiel:
    """Carga los certificados de la e.firma con cfdiclient (argumentos posicionales)."""
    try:
        return Fiel(cer_bytes, key_bytes, password)
    except Exception as e:
        logger.error(f"Error cargando Fiel: {e}")
        raise HTTPException(
            status_code=400, 
            detail=f"Error al validar e.firma o contraseña: {str(e)}"
        )

def obtener_token(fiel: Fiel) -> str:
    """Obtiene el token de sesión autenticado contra el SAT."""
    try:
        auth = Autenticacion(fiel)
        token = auth.obtener_token()
        if not token:
            raise Exception("El SAT no devolvió un token de autorización.")
        return token
    except Exception as e:
        logger.error(f"Falla de autenticación en el SAT: {e}")
        raise HTTPException(
            status_code=401, 
            detail=f"No se pudo autenticar con el SAT: {str(e)}"
        )

def extraer_xmls_recursivo(paquete_data) -> list:
    """Extrae XMLs manejando Base64 y paquetes anidados (.zip dentro de .zip)."""
    if isinstance(paquete_data, str):
        try:
            paquete_bytes = base64.b64decode(paquete_data)
        except Exception:
            paquete_bytes = paquete_data.encode("utf-8")
    elif isinstance(paquete_data, bytes):
        try:
            paquete_bytes = base64.b64decode(paquete_data)
        except Exception:
            paquete_bytes = paquete_data
    else:
        return []

    xml_encontrados = []
    try:
        with zipfile.ZipFile(io.BytesIO(paquete_bytes)) as z_padre:
            for nombre in z_padre.namelist():
                contenido = z_padre.read(nombre)
                if nombre.lower().endswith(".zip"):
                    try:
                        with zipfile.ZipFile(io.BytesIO(contenido)) as z_hijo:
                            for n2 in z_hijo.namelist():
                                if n2.lower().endswith(".xml"):
                                    c_xml = z_hijo.read(n2).decode("utf-8", errors="ignore")
                                    xml_encontrados.append({
                                        "archivo": n2,
                                        "xml_contenido": c_xml
                                    })
                    except Exception as e_zip:
                        logger.warning(f"Error abriendo ZIP interno {nombre}: {e_zip}")
                elif nombre.lower().endswith(".xml"):
                    c_xml = contenido.decode("utf-8", errors="ignore")
                    xml_encontrados.append({
                        "archivo": nombre,
                        "xml_contenido": c_xml
                    })
    except Exception as e:
        logger.error(f"Error descomprimiendo paquete: {str(e)}")

    return xml_encontrados

@app.get("/")
def ruta_raiz():
    return {
        "status": "ok", 
        "servicio": "SAT Descarga Masiva API",
        "motor": "cfdiclient",
        "version": "2.0.0"
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
    token = obtener_token(fiel)

    f_inicio = formatear_fecha_sat(fecha_inicio, es_fin=False)
    f_fin = formatear_fecha_sat(fecha_fin, es_fin=True)
    rfc_limpio = rfc.strip().upper()
    es_emitidos = tipo.lower() == "emitidos"

    logger.info(f"Solicitando {tipo} para RFC {rfc_limpio} de {f_inicio} a {f_fin}")

    try:
        cliente_solicita = SolicitaDescarga(fiel)
        kwargs = {
            "token": token,
            "rfc_solicitante": rfc_limpio,
            "fecha_inicial": f_inicio,
            "fecha_final": f_fin,
            "tipo_solicitud": "CFDI"
        }
        if es_emitidos:
            kwargs["rfc_emisor"] = rfc_limpio
        else:
            kwargs["rfc_receptor"] = rfc_limpio

        res = cliente_solicita.solicitar_descarga(**kwargs)
        cod_estatus = str(res.get("cod_estatus", res.get("CodEstatus", "5000")))

        if cod_estatus != "5000":
            raise HTTPException(
                status_code=400,
                detail=f"SAT Código {cod_estatus}: {res.get('mensaje', res.get('Mensaje', 'Error en la solicitud'))}"
            )

        id_solicitud = res.get("id_solicitud", res.get("IdSolicitud"))
        return {
            "status": "success",
            "id_solicitud": id_solicitud,
            "codigo_estatus": cod_estatus,
            "mensaje": res.get("mensaje", res.get("Mensaje", "Solicitud aceptada"))
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en solicitar_descarga: {e}")
        raise HTTPException(status_code=502, detail=f"Error en el Web Service del SAT: {str(e)}")

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
    token = obtener_token(fiel)

    try:
        cliente_verifica = VerificaSolicitudDescarga(fiel)
        res = cliente_verifica.verificar_descarga(
            token=token,
            rfc_solicitante=fiel.rfc,
            id_solicitud=id_solicitud
        )
        
        paquetes = res.get("paquetes", res.get("IdsPaquetes", []))
        estado = str(res.get("estado_solicitud", res.get("EstadoSolicitud", "2")))
        numero_cfdis = res.get("numero_cfdis", res.get("NumeroCFDIs", len(paquetes)))

        return {
            "id_solicitud": id_solicitud,
            "estado_solicitud": estado,
            "codigo_estado_solicitud": str(res.get("codigo_estado_solicitud", "5000")),
            "numero_cfdis": numero_cfdis,
            "paquetes_listos": len(paquetes) > 0 and estado == "3",
            "ids_paquetes": paquetes
        }
    except Exception as e:
        logger.error(f"Error en verificar_descarga: {e}")
        raise HTTPException(status_code=502, detail=f"Error al consultar estado al SAT: {str(e)}")

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
    token = obtener_token(fiel)

    try:
        cliente_descarga = DescargaMasiva(fiel)
        res = cliente_descarga.descargar_paquete(
            token=token,
            rfc_solicitante=fiel.rfc,
            id_paquete=id_paquete
        )

        paquete_raw = res.get("paquete_b64", res.get("PaqueteB64", res.get("paquete")))
        if not paquete_raw:
            raise HTTPException(status_code=404, detail="El SAT no devolvió contenido para este paquete.")

        xmls = extraer_xmls_recursivo(paquete_raw)
        logger.info(f"Paquete {id_paquete}: {len(xmls)} XMLs extraídos con éxito.")

        return {
            "id_paquete": id_paquete,
            "total_xmls": len(xmls),
            "comprobantes": xmls
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en descargar_paquete: {e}")
        raise HTTPException(status_code=502, detail=f"Error al descargar el paquete del SAT: {str(e)}")
