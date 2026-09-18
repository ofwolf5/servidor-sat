from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import base64
import zipfile
import io

app = FastAPI(
    title="Microservicio de Descarga Masiva SAT",
    description="Backend puente para Lovable",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Carga dinámica y segura de la librería satcfdi
# ---------------------------------------------------------------------------
def obtener_herramientas_sat():
    """Localiza las clases de firma y descarga masiva en la librería instalada."""
    import satcfdi
    
    # Localizar clase para firma
    signer_cls = None
    for mod_name in ['satcfdi.models', 'satcfdi.signer', 'satcfdi.pfx', 'satcfdi']:
        try:
            m = __import__(mod_name, fromlist=['Certificate', 'Signer', 'Fiel'])
            signer_cls = getattr(m, 'Certificate', getattr(m, 'Signer', getattr(m, 'Fiel', None)))
            if signer_cls:
                break
        except ImportError:
            continue

    # Localizar clase para descarga masiva
    ws_cls = None
    for mod_name in ['satcfdi.ws.consulta_masiva', 'satcfdi.portal', 'satcfdi.ws']:
        try:
            m = __import__(mod_name, fromlist=['ConsultaMasiva', 'PortalDescargaMasiva', 'DescargaMasiva'])
            ws_cls = getattr(m, 'ConsultaMasiva', getattr(m, 'PortalDescargaMasiva', getattr(m, 'DescargaMasiva', None)))
            if ws_cls:
                break
        except ImportError:
            continue

    return signer_cls, ws_cls

def cargar_fiel(cer_bytes: bytes, key_bytes: bytes, password: str):
    """Carga y valida los certificados de la e.firma."""
    signer_cls, _ = obtener_herramientas_sat()
    if not signer_cls:
        raise HTTPException(status_code=500, detail="Módulo criptográfico no encontrado en satcfdi")
    
    try:
        # Intenta métodos comunes de inicialización
        if hasattr(signer_cls, "load"):
            return signer_cls.load(certificate=cer_bytes, key=key_bytes, password=password.encode("utf-8"))
        try:
            return signer_cls(cer=cer_bytes, key=key_bytes, password=password.encode("utf-8"))
        except TypeError:
            return signer_cls(certificate=cer_bytes, key=key_bytes, password=password.encode("utf-8"))
    except Exception as e:
        raise HTTPException(
            status_code=400, 
            detail=f"Error validando e.firma o contraseña: {str(e)}"
        )

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/")
def ruta_raiz():
    signer_cls, ws_cls = obtener_herramientas_sat()
    return {
        "status": "ok", 
        "servicio": "SAT Descarga Masiva API",
        "modulo_firma": bool(signer_cls),
        "modulo_ws": bool(ws_cls)
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
    _, ws_cls = obtener_herramientas_sat()
    if not ws_cls:
        raise HTTPException(status_code=500, detail="Módulo de consulta masiva no disponible")

    cer_bytes = await cer_file.read()
    key_bytes = await key_file.read()
    fiel = cargar_fiel(cer_bytes, key_bytes, password)
    cliente = ws_cls(fiel=fiel)

    try:
        resultado = cliente.solicita(
            rfc_emisor=rfc if tipo.lower() == "emitidos" else None,
            rfc_receptor=rfc if tipo.lower() == "recibidos" else None,
            fecha_inicial=f"{fecha_inicio}T00:00:00",
            fecha_final=f"{fecha_fin}T23:59:59",
            tipo_solicitud="CFDI"
        )
        return {
            "status": "success",
            "id_solicitud": resultado.get("IdSolicitud"),
            "codigo_estatus": resultado.get("CodEstatus"),
            "mensaje": resultado.get("Mensaje")
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Falla al conectar con el SAT: {str(e)}")

@app.post("/api/sat/verificar")
async def verificar_solicitud(
    cer_file: UploadFile = File(...),
    key_file: UploadFile = File(...),
    password: str = Form(...),
    id_solicitud: str = Form(...)
):
    _, ws_cls = obtener_herramientas_sat()
    if not ws_cls:
        raise HTTPException(status_code=500, detail="Módulo de consulta masiva no disponible")

    cer_bytes = await cer_file.read()
    key_bytes = await key_file.read()
    fiel = cargar_fiel(cer_bytes, key_bytes, password)
    cliente = ws_cls(fiel=fiel)

    try:
        verificacion = cliente.verifica(id_solicitud=id_solicitud)
        paquetes = verificacion.get("IdsPaquetes", [])

        return {
            "id_solicitud": id_solicitud,
            "estado_solicitud": verificacion.get("EstadoSolicitud"),
            "codigo_estado_solicitud": verificacion.get("CodigoEstadoSolicitud"),
            "numero_cfdis": verificacion.get("NumeroCFDIs", 0),
            "paquetes_listos": len(paquetes) > 0,
            "ids_paquetes": paquetes
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Error consultando estatus: {str(e)}")

@app.post("/api/sat/descargar-paquete")
async def descargar_paquete(
    cer_file: UploadFile = File(...),
    key_file: UploadFile = File(...),
    password: str = Form(...),
    id_paquete: str = Form(...)
):
    _, ws_cls = obtener_herramientas_sat()
    if not ws_cls:
        raise HTTPException(status_code=500, detail="Módulo de consulta masiva no disponible")

    cer_bytes = await cer_file.read()
    key_bytes = await key_file.read()
    fiel = cargar_fiel(cer_bytes, key_bytes, password)
    cliente = ws_cls(fiel=fiel)

    try:
        respuesta = cliente.descarga(id_paquete=id_paquete)
        paquete_b64 = respuesta.get("PaqueteB64")

        if not paquete_b64:
            raise HTTPException(status_code=404, detail="El SAT no devolvió contenido para este paquete.")

        archivo_zip = io.BytesIO(base64.b64decode(paquete_b64))
        xml_list = []

        with zipfile.ZipFile(archivo_zip, "r") as zip_ref:
            for file_name in zip_ref.namelist():
                if file_name.endswith(".xml"):
                    contenido_xml = zip_ref.read(file_name).decode("utf-8", errors="ignore")
                    xml_list.append({
                        "archivo": file_name,
                        "xml_contenido": contenido_xml
                    })

        return {
            "id_paquete": id_paquete,
            "total_xmls": len(xml_list),
            "comprobantes": xml_list
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Error descargando paquete: {str(e)}")
