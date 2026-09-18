from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import xml.etree.ElementTree as ET
import base64
import zipfile
import io
import requests
import uuid
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sat_service")

app = FastAPI(
    title="Microservicio de Descarga Masiva SAT",
    description="Backend oficial SOAP SAT para Lovable",
    version="4.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Criptografía e.firma
# ---------------------------------------------------------------------------

class FielNativa:
    def __init__(self, cer_bytes: bytes, key_bytes: bytes, password: str):
        self.cert = x509.load_der_x509_certificate(cer_bytes)
        self.cert_b64 = base64.b64encode(cer_bytes).decode("utf-8")
        
        # Extraer RFC del certificado
        self.rfc = ""
        for attr in self.cert.subject:
            # OID común para RFC o serialNumber en certificados del SAT
            if attr.oid._name in ("serialNumber", "x500UniqueIdentifier"):
                val = attr.value.strip()
                if " " in val:
                    val = val.split(" ")[0]
                self.rfc = val
        
        try:
            self.key = load_der_private_key(key_bytes, password=password.encode("utf-8"))
        except Exception:
            self.key = load_der_private_key(key_bytes, password=None)

    def firmar_sha1(self, data: bytes) -> str:
        firma = self.key.sign(data, padding.PKCS1v15(), hashes.SHA1())
        return base64.b64encode(firma).decode("utf-8")

def formatear_fecha(fecha_str: str, es_fin: bool = False) -> str:
    fecha_limpia = fecha_str.strip()
    if "T" not in fecha_limpia:
        hora = "23:59:59" if es_fin else "00:00:00"
        return f"{fecha_limpia}T{hora}"
    return fecha_limpia

# ---------------------------------------------------------------------------
# SOAP del SAT: Autenticación
# ---------------------------------------------------------------------------

def obtener_token_sat(fiel: FielNativa) -> str:
    """Solicita token oficial de autenticación al SAT."""
    ahora = datetime.now(timezone.utc)
    creado = ahora.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    expira = (ahora + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    timestamp = f'<u:Timestamp xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" u:Id="_0"><u:Created>{creado}</u:Created><u:Expires>{expira}</u:Expires></u:Timestamp>'
    
    digest_hash = hashes.Hash(hashes.SHA1())
    digest_hash.update(timestamp.encode("utf-8"))
    digest_val = base64.b64encode(digest_hash.finalize()).decode("utf-8")

    signed_info = f'<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI="#_0"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>{digest_val}</DigestValue></Reference></SignedInfo>'
    
    firma_b64 = fiel.firmar_sha1(signed_info.encode("utf-8"))

    soap_envelope = f"""<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
    <s:Header>
        <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            {timestamp}
            <o:BinarySecurityToken u:Id="uuid-{uuid.uuid4()}-1" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{fiel.cert_b64}</o:BinarySecurityToken>
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
                {signed_info}
                <SignatureValue>{firma_b64}</SignatureValue>
                <KeyInfo>
                    <o:SecurityTokenReference>
                        <o:Reference ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" URI="#_0"/>
                    </o:SecurityTokenReference>
                </KeyInfo>
            </Signature>
        </o:Security>
    </s:Header>
    <s:Body>
        <Autentica xmlns="http://DescargaMasivaTerceros.sat.gob.mx"/>
    </s:Body>
</s:Envelope>"""

    headers = {
        "Content-Type": "text/xml;charset=utf-8",
        "SOAPAction": "http://DescargaMasivaTerceros.sat.gob.mx/IAutenticacion/Autentica"
    }
    url = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc"
    res = requests.post(url, data=soap_envelope.encode("utf-8"), headers=headers, timeout=20)
    
    root = ET.fromstring(res.text)
    token_elem = root.find(".//{http://DescargaMasivaTerceros.sat.gob.mx}token")
    if token_elem is not None and token_elem.text:
        return token_elem.text
    raise HTTPException(status_code=401, detail=f"El SAT rechazó la autenticación: {res.text[:200]}")

# ---------------------------------------------------------------------------
# SOAP del SAT: Descompresión de Paquetes
# ---------------------------------------------------------------------------

def extraer_xmls_reales(paquete_b64_raw: str) -> list:
    """Decodifica Base64 y extrae XMLs tanto directos como anidados en .zip."""
    if not paquete_b64_raw:
        return []

    # Limpieza estricta de Base64
    limpio = paquete_b64_raw.strip().replace("\n", "").replace("\r", "").replace(" ", "")
    try:
        paquete_bytes = base64.b64decode(limpio)
    except Exception as e:
        logger.error(f"Error decodificando Base64: {e}")
        return []

    logger.info(f"Bytes del ZIP recibido del SAT: {len(paquete_bytes)}")

    xmls = []
    try:
        with zipfile.ZipFile(io.BytesIO(paquete_bytes)) as z_padre:
            nombres = z_padre.namelist()
            logger.info(f"Nombres en el ZIP del SAT ({len(nombres)} archivos): {nombres[:10]}")

            for nombre in nombres:
                contenido = z_padre.read(nombre)
                # Caso de ZIP anidado (común cuando son muchas facturas)
                if nombre.lower().endswith(".zip"):
                    try:
                        with zipfile.ZipFile(io.BytesIO(contenido)) as z_hijo:
                            for n2 in z_hijo.namelist():
                                if n2.lower().endswith(".xml"):
                                    xml_texto = z_hijo.read(n2).decode("utf-8", errors="ignore")
                                    xmls.append({"archivo": n2, "xml_contenido": xml_texto})
                    except Exception as e_anidado:
                        logger.warning(f"Error en sub-ZIP {nombre}: {e_anidado}")
                elif nombre.lower().endswith(".xml"):
                    xml_texto = contenido.decode("utf-8", errors="ignore")
                    xmls.append({"archivo": nombre, "xml_contenido": xml_texto})
    except Exception as e:
        logger.error(f"Error abriendo ZIP del SAT: {e}")

    logger.info(f"Total de XMLs reales extraídos: {len(xmls)}")
    return xmls

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/")
def ruta_raiz():
    return {
        "status": "ok", 
        "servicio": "SAT Descarga Masiva API Oficial",
        "modo": "SOAP Puro",
        "version": "4.0.0"
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

    try:
        fiel = FielNativa(cer_bytes, key_bytes, password)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error en certificados e.firma: {str(e)}")

    token = obtener_token_sat(fiel)

    f_inicio = formatear_fecha(fecha_inicio, es_fin=False)
    f_fin = formatear_fecha(fecha_fin, es_fin=True)
    rfc_solicitante = rfc.strip().upper()
    es_emitidos = tipo.lower() == "emitidos"

    # Construcción de la solicitud al Web Service del SAT
    attr_emisor = f'RfcEmisor="{rfc_solicitante}"' if es_emitidos else ''
    attr_receptor = f'RfcReceptor="{rfc_solicitante}"' if not es_emitidos else ''

    cuerpo_solicitud = f'<solicitud FechaInicial="{f_inicio}" FechaFinal="{f_fin}" {attr_emisor} {attr_receptor} RfcSolicitante="{rfc_solicitante}" TipoSolicitud="CFDI"/>'
    
    # Firma del nodo solicitud
    digest_hash = hashes.Hash(hashes.SHA1())
    digest_hash.update(cuerpo_solicitud.encode("utf-8"))
    digest_val = base64.b64encode(digest_hash.finalize()).decode("utf-8")

    signed_info = f'<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>{digest_val}</DigestValue></Reference></SignedInfo>'
    firma_b64 = fiel.firmar_sha1(signed_info.encode("utf-8"))

    soap_req = f"""<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
    <s:Header/>
    <s:Body>
        <SolicitaDescarga xmlns="http://DescargaMasivaTerceros.sat.gob.mx">
            <solicitud FechaInicial="{f_inicio}" FechaFinal="{f_fin}" {attr_emisor} {attr_receptor} RfcSolicitante="{rfc_solicitante}" TipoSolicitud="CFDI">
                <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
                    {signed_info}
                    <SignatureValue>{firma_b64}</SignatureValue>
                    <KeyInfo>
                        <X509Data>
                            <X509IssuerSerial>
                                <X509IssuerName>{fiel.cert.issuer.rfc4514_string()}</X509IssuerName>
                                <X509SerialNumber>{fiel.cert.serial_number}</X509SerialNumber>
                            </X509IssuerSerial>
                            <X509Certificate>{fiel.cert_b64}</X509Certificate>
                        </X509Data>
                    </KeyInfo>
                </Signature>
            </solicitud>
        </SolicitaDescarga>
    </s:Body>
</s:Envelope>"""

    headers = {
        "Content-Type": "text/xml;charset=utf-8",
        "SOAPAction": "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescarga",
        "Authorization": f'WRAP access_token="{token}"'
    }

    url = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc"
    resp = requests.post(url, data=soap_req.encode("utf-8"), headers=headers, timeout=30)
    
    root = ET.fromstring(resp.text)
    res_elem = root.find(".//{http://DescargaMasivaTerceros.sat.gob.mx}SolicitaDescargaResult")
    
    if res_elem is None:
        raise HTTPException(status_code=502, detail=f"Respuesta inesperada del SAT: {resp.text[:300]}")

    cod_estatus = res_elem.get("CodEstatus", "5000")
    mensaje = res_elem.get("Mensaje", "")
    id_solicitud = res_elem.get("IdSolicitud", "")

    if cod_estatus != "5000":
        raise HTTPException(status_code=400, detail=f"SAT Código {cod_estatus}: {mensaje}")

    logger.info(f"Solicitud aceptada por el SAT con ID real: {id_solicitud}")
    return {
        "status": "success",
        "id_solicitud": id_solicitud,
        "codigo_estatus": cod_estatus,
        "mensaje": mensaje
    }

@app.post("/api/sat/verificar")
async def verificar_solicitud(
    cer_file: UploadFile = File(...),
    key_file: UploadFile = File(...),
    password: str = Form(...),
    id_solicitud: str = Form(...)
):
    cer_bytes = await cer_file.read()
    key_bytes = await key_file.read()
    fiel = FielNativa(cer_bytes, key_bytes, password)
    token = obtener_token_sat(fiel)

    cuerpo_verif = f'<solicitud IdSolicitud="{id_solicitud}" RfcSolicitante="{fiel.rfc}"/>'
    
    digest_hash = hashes.Hash(hashes.SHA1())
    digest_hash.update(cuerpo_verif.encode("utf-8"))
    digest_val = base64.b64encode(digest_hash.finalize()).decode("utf-8")

    signed_info = f'<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>{digest_val}</DigestValue></Reference></SignedInfo>'
    firma_b64 = fiel.firmar_sha1(signed_info.encode("utf-8"))

    soap_req = f"""<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
    <s:Header/>
    <s:Body>
        <VerificaSolicitudDescarga xmlns="http://DescargaMasivaTerceros.sat.gob.mx">
            <solicitud IdSolicitud="{id_solicitud}" RfcSolicitante="{fiel.rfc}">
                <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
                    {signed_info}
                    <SignatureValue>{firma_b64}</SignatureValue>
                    <KeyInfo>
                        <X509Data>
                            <X509IssuerSerial>
                                <X509IssuerName>{fiel.cert.issuer.rfc4514_string()}</X509IssuerName>
                                <X509SerialNumber>{fiel.cert.serial_number}</X509SerialNumber>
                            </X509IssuerSerial>
                            <X509Certificate>{fiel.cert_b64}</X509Certificate>
                        </X509Data>
                    </KeyInfo>
                </Signature>
            </solicitud>
        </VerificaSolicitudDescarga>
    </s:Body>
</s:Envelope>"""

    headers = {
        "Content-Type": "text/xml;charset=utf-8",
        "SOAPAction": "http://DescargaMasivaTerceros.sat.gob.mx/IVerificaSolicitudDescargaService/VerificaSolicitudDescarga",
        "Authorization": f'WRAP access_token="{token}"'
    }

    url = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/VerificaSolicitudDescargaService.svc"
    resp = requests.post(url, data=soap_req.encode("utf-8"), headers=headers, timeout=30)

    root = ET.fromstring(resp.text)
    res_elem = root.find(".//{http://DescargaMasivaTerceros.sat.gob.mx}VerificaSolicitudDescargaResult")

    if res_elem is None:
        raise HTTPException(status_code=502, detail=f"Error en respuesta de verificación: {resp.text[:300]}")

    estado = res_elem.get("EstadoSolicitud", "2")  # 1: Aceptada, 2: En Proceso, 3: Terminada, 4: Error, 5: Rechazada
    numero_cfdis = int(res_elem.get("NumeroCFDIs", "0"))
    
    # Extraer los paquetes entregados por el SAT
    paquetes = []
    for pkg in res_elem.findall(".//{http://DescargaMasivaTerceros.sat.gob.mx}IdsPaquetes"):
        if pkg.text:
            paquetes.append(pkg.text.strip())

    logger.info(f"Verificación IdSolicitud {id_solicitud}: Estado={estado}, CFDIs={numero_cfdis}, Paquetes={paquetes}")

    return {
        "id_solicitud": id_solicitud,
        "estado_solicitud": estado,
        "codigo_estado_solicitud": res_elem.get("CodigoEstadoSolicitud", ""),
        "numero_cfdis": numero_cfdis,
        "paquetes_listos": estado == "3" and len(paquetes) > 0,
        "ids_paquetes": paquetes
    }

@app.post("/api/sat/descargar-paquete")
async def descargar_paquete(
    cer_file: UploadFile = File(...),
    key_file: UploadFile = File(...),
    password: str = Form(...),
    id_paquete: str = Form(...)
):
    cer_bytes = await cer_file.read()
    key_bytes = await key_file.read()
    fiel = FielNativa(cer_bytes, key_bytes, password)
    token = obtener_token_sat(fiel)

    logger.info(f"Descargando paquete real del SAT: {id_paquete}")

    cuerpo_descarga = f'<peticionDescarga IdPaquete="{id_paquete}" RfcSolicitante="{fiel.rfc}"/>'
    
    digest_hash = hashes.Hash(hashes.SHA1())
    digest_hash.update(cuerpo_descarga.encode("utf-8"))
    digest_val = base64.b64encode(digest_hash.finalize()).decode("utf-8")

    signed_info = f'<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>{digest_val}</DigestValue></Reference></SignedInfo>'
    firma_b64 = fiel.firmar_sha1(signed_info.encode("utf-8"))

    soap_req = f"""<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
    <s:Header/>
    <s:Body>
        <PeticionDescargaMasiva xmlns="http://DescargaMasivaTerceros.sat.gob.mx">
            <peticionDescarga IdPaquete="{id_paquete}" RfcSolicitante="{fiel.rfc}">
                <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
                    {signed_info}
                    <SignatureValue>{firma_b64}</SignatureValue>
                    <KeyInfo>
                        <X509Data>
                            <X509IssuerSerial>
                                <X509IssuerName>{fiel.cert.issuer.rfc4514_string()}</X509IssuerName>
                                <X509SerialNumber>{fiel.cert.serial_number}</X509SerialNumber>
                            </X509IssuerSerial>
                            <X509Certificate>{fiel.cert_b64}</X509Certificate>
                        </X509Data>
                    </KeyInfo>
                </Signature>
            </peticionDescarga>
        </PeticionDescargaMasiva>
    </s:Body>
</s:Envelope>"""

    headers = {
        "Content-Type": "text/xml;charset=utf-8",
        "SOAPAction": "http://DescargaMasivaTerceros.sat.gob.mx/IDescargaMasivaTercerosService/Descargar",
        "Authorization": f'WRAP access_token="{token}"'
    }

    url = "https://cfdidescargamasiva.clouda.sat.gob.mx/DescargaMasivaService.svc"
    resp = requests.post(url, data=soap_req.encode("utf-8"), headers=headers, timeout=60)

    root = ET.fromstring(resp.text)
    res_elem = root.find(".//{http://DescargaMasivaTerceros.sat.gob.mx}RespuestaDescargaMasivaTercerosSalida")
    
    if res_elem is None:
        raise HTTPException(status_code=502, detail=f"Respuesta inesperada al descargar paquete: {resp.text[:300]}")

    paquete_elem = res_elem.find(".//{http://DescargaMasivaTerceros.sat.gob.mx}Paquete")
    if paquete_elem is None or not paquete_elem.text:
        cod_estatus = res_elem.get("CodEstatus", "Desconocido")
        mensaje = res_elem.get("Mensaje", "Sin mensaje")
        raise HTTPException(
            status_code=404, 
            detail=f"El SAT no devolvió contenido para el paquete {id_paquete}. Estatus SAT: {cod_estatus} - {mensaje}"
        )

    # Extraer los XMLs auténticos
    xmls = extraer_xmls_reales(paquete_elem.text)

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
