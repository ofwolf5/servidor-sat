from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import base64
import zipfile
import io

# Importaciones universales y estables de satcfdi
import satcfdi
from satcfdi import Signer
from satcfdi.ws.consulta_masiva import ConsultaMasiva, TipoDescargaMasivaTerceros

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

def cargar_fiel(cer_bytes: bytes, key_bytes: bytes, password: str):
    """Carga y valida los certificados de la e.firma en memoria."""
    try:
        # En satcfdi 2026+ Signer acepta directamente los bytes o el método load
        if hasattr(Signer, "load"):
            return Signer.load(certificate=cer_bytes, key=key_bytes, password=password.encode("utf-8"))
        return Signer(cer=cer_bytes, key=key_bytes, password=password.encode("utf-8"))
    except Exception as e:
        raise HTTPException(
            status_code=400, 
            detail=f"Error con los archivos de la e.firma o contraseña: {str(e)}"
        )

@app.get("/")
def ruta_raiz():
    return {
        "status": "ok", 
        "servicio": "SAT Descarga Masiva API", 
        "version_libreria": getattr(satcfdi, "__version__", "activa")
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
    cliente = ConsultaMasiva(fiel=fiel)

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
    cer_bytes = await cer_file.read()
    key_bytes = await key_file.read()

    fiel = cargar_fiel(cer_bytes, key_bytes, password)
    cliente = ConsultaMasiva(fiel=fiel)

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
    cer_bytes = await cer_file.read()
    key_bytes = await key_file.read()

    fiel = cargar_fiel(cer_bytes, key_bytes, password)
    cliente = ConsultaMasiva(fiel=fiel)

    try:
        respuesta_descarga = cliente.descarga(id_paquete=id_paquete)
        paquete_b64 = respuesta_descarga.get("PaqueteB64")

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
        raise HTTPException(status_code=502, detail=f"Error en la descarga del paquete: {str(e)}")
