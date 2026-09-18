from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import base64
import zipfile
import io
import logging

from satcfdi.models import Signer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sat_service")

app = FastAPI(
    title="Microservicio de Descarga Masiva SAT",
    description="Backend puente para Lovable",
    version="1.2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def formatear_fecha_sat(fecha_str: str, es_fin: bool = False) -> str:
    """Asegura formato ISO YYYY-MM-DDTHH:MM:SS requerido por el SAT."""
    fecha_limpia = fecha_str.strip()
    if "T" not in fecha_limpia:
        hora = "23:59:59" if es_fin else "00:00:00"
        return f"{fecha_limpia}T{hora}"
    return fecha_limpia

def cargar_fiel(cer_bytes: bytes, key_bytes: bytes, password: str) -> Signer:
    """Carga y valida los certificados de la e.firma con Signer.load."""
    try:
        return Signer.load(
            certificate=cer_bytes,
            key=key_bytes,
            password=password.encode("utf-8")
        )
    except Exception as e:
        logger.error(f"Error cargando certificados: {e}")
        raise HTTPException(
            status_code=400, 
            detail=f"Error validando e.firma o contraseña: {str(e)}"
        )

def obtener_portal_sat(fiel: Signer):
    """
    Inicializa el cliente de conexión con el SAT pasando la firma de forma POSICIONAL.
    Evita el error 'PortalManager got an unexpected keyword argument fiel'.
    """
    try:
        from satcfdi.portal import PortalManager
        return PortalManager(fiel)
    except (ImportError, TypeError):
        pass

    try:
        from satcfdi.portal import SATPortal
        return SATPortal(fiel)
    except (ImportError, TypeError):
        pass

    from satcfdi.portal.portal import PortalManager
    return PortalManager(fiel)

def extraer_xmls_recursivo(paquete_data) -> list:
    """Extrae XMLs manejando Base64 y ZIPs anidados (.zip dentro de .zip)."""
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
            nombres = z_padre.namelist()
            logger.info(f"Archivos encontrados en el paquete principal: {len(nombres)}")
            
            for nombre in nombres:
                contenido = z_padre.read(nombre)
                # Caso de ZIP anidado
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
                        logger.warning(f"No se pudo descomprimir sub-archivo {nombre}: {e_zip}")
                # Caso de XML directo
                elif nombre.lower().endswith(".xml"):
                    c_xml = contenido.decode("utf-8", errors="ignore")
                    xml_encontrados.append({
                        "archivo": nombre,
                        "xml_contenido": c_xml
                    })
    except Exception as e:
        logger.error(f"Error procesando ZIP: {str(e)}")

    return xml_encontrados

@app.get("/")
def ruta_raiz():
    return {
        "status": "ok", 
        "servicio": "SAT Descarga Masiva API",
        "version": "1.2.0"
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

    f_inicio = formatear_fecha_sat(fecha_inicio, es_fin=False)
    f_fin = formatear_fecha_sat(fecha_fin, es_fin=True)
    rfc_limpio = rfc.strip().upper()
    es_emitidos = tipo.lower() == "emitidos"

    logger.info(f"Solicitando descarga al SAT para RFC: {rfc_limpio}, tipo: {tipo}")

    portal = obtener_portal_sat(fiel)

    try:
        kwargs = {
            "fecha_inicial": f_inicio,
            "fecha_final": f_fin,
            "tipo_solicitud": "CFDI",
            "rfc_solicitante": rfc_limpio
        }
        if es_emitidos:
            kwargs["rfc_emisor"] = rfc_limpio
        else:
            kwargs["rfc_receptor"] = rfc_limpio

        # Llamada directa al Web Service oficial del SAT
        cliente_dm = getattr(portal, "descarga_masiva", portal)
        res = cliente_dm.solicita(**kwargs)
        
        cod_estatus = str(res.get("CodEstatus", "5000"))
        if cod_estatus != "5000":
            raise HTTPException(
                status_code=400,
                detail=f"SAT Código {cod_estatus}: {res.get('Mensaje', 'Error en la solicitud')}"
            )

        return {
            "status": "success",
            "id_solicitud": res.get("IdSolicitud"),
            "codigo_estatus": cod_estatus,
            "mensaje": res.get("Mensaje", "Solicitud aceptada por el SAT")
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en solicitud con el SAT: {str(e)}")
        raise HTTPException(status_code=502, detail=f"Error comunicando con el SAT: {str(e)}")

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

    portal = obtener_portal_sat(fiel)

    try:
        cliente_dm = getattr(portal, "descarga_masiva", portal)
        res = cliente_dm.verifica(id_solicitud=id_solicitud)
        
        paquetes = res.get("IdsPaquetes", [])
        estado_solicitud = str(res.get("EstadoSolicitud", "2")) # 1: Aceptada, 2: En Proceso, 3: Terminada
        
        return {
            "id_solicitud": id_solicitud,
            "estado_solicitud": estado_solicitud,
            "codigo_estado_solicitud": str(res.get("CodigoEstadoSolicitud", "5000")),
            "numero_cfdis": res.get("NumeroCFDIs", len(paquetes)),
            "paquetes_listos": len(paquetes) > 0 and estado_solicitud == "3",
            "ids_paquetes": paquetes
        }
    except Exception as e:
        logger.error(f"Error verificando con el SAT: {str(e)}")
        raise HTTPException(status_code=502, detail=f"Error consultando estatus al SAT: {str(e)}")

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

    portal = obtener_portal_sat(fiel)

    try:
        cliente_dm = getattr(portal, "descarga_masiva", portal)
        res = cliente_dm.descarga(id_paquete=id_paquete)
        
        paquete_raw = res.get("Paquete") or res.get("PaqueteB64")
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
        logger.error(f"Error en descarga: {str(e)}")
        raise HTTPException(status_code=502, detail=f"Falla al descargar paquete del SAT: {str(e)}")
