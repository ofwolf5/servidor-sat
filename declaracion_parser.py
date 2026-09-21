import io
import re
from typing import Dict, Any, Optional
import pypdf

def limpiar_monto(texto_monto: Optional[str]) -> float:
    """Convierte cadenas como '$ 145,230.00' o '145,230' a float."""
    if not texto_monto:
        return 0.0
    limpio = re.sub(r"[^\d.-]", "", texto_monto)
    try:
        return float(limpio) if limpio else 0.0
    except ValueError:
        return 0.0

def extraer_texto_pdf(pdf_bytes: bytes) -> str:
    """Extrae todo el texto plano manteniendo orden de lectura de páginas."""
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    texto_total = []
    for pagina in reader.pages:
        texto = pagina.extract_text()
        if texto:
            texto_total.append(texto)
    return "\n".join(texto_total)

def parsear_acuse_sat(pdf_bytes: bytes) -> Dict[str, Any]:
    """
    Parsea acuses de declaraciones provisionales/definitivas del SAT y devuelve
    un diccionario estructurado con metadatos e impuestos detallados.
    """
    texto = extraer_texto_pdf(pdf_bytes)
    
    # Normalización básica de saltos y espacios múltiples
    lineas = [l.strip() for l in texto.split("\n") if l.strip()]
    texto_unificado = " ".join(lineas)

    # -------------------------------------------------------------------------
    # 1. Metadatos Generales
    # -------------------------------------------------------------------------
    rfc_match = re.search(r"RFC:\s*([A-Z&Ñ]{3,4}\d{6}[A-V1-9][A-Z\d]{2})", texto, re.IGNORECASE)
    folio_match = re.search(r"(?:Número de operación|No\. de operación|Folio):\s*(\d{10,20})", texto, re.IGNORECASE)
    fecha_pres_match = re.search(r"Fecha y hora de presentación:\s*(\d{2}/\d{2}/\d{4}(?:\s+\d{2}:\d{2}(?::\d{2})?)?)", texto, re.IGNORECASE)
    ejercicio_match = re.search(r"Ejercicio:\s*(\d{4})", texto, re.IGNORECASE)
    periodo_match = re.search(r"Periodo:\s*([A-Za-z]+(?:\s*-\s*[A-Za-z]+)?)", texto, re.IGNORECASE)
    tipo_dec_match = re.search(r"Tipo de declaración:\s*([A-Za-z\s]+?)(?:\s{2,}|Fecha|Número|$)", texto, re.IGNORECASE)

    # Buscar Razón Social / Denominación
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

    # -------------------------------------------------------------------------
    # 2. Extracción de Impuesto al Valor Agregado (IVA)
    # -------------------------------------------------------------------------
    m_iva_16 = re.search(r"(?:Total de actos o actividades gravados al 16%|Actividades gravadas al 16%)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_iva_16:
        resultado["iva"]["actos_gravados_16"] = limpiar_monto(m_iva_16.group(1))

    m_iva_tras = re.search(r"(?:IVA trasladado|Impuesto causado|Total del IVA causado)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_iva_tras:
        resultado["iva"]["iva_trasladado_cobrado"] = limpiar_monto(m_iva_tras.group(1))

    m_iva_acred = re.search(r"(?:Total del IVA acreditable|IVA acreditable del periodo|IVA acreditable)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_iva_acred:
        resultado["iva"]["iva_acreditable_pagado"] = limpiar_monto(m_iva_acred.group(1))

    m_iva_ret_le_efectuaron = re.search(r"(?:IVA que le retuvieron|Retenciones de IVA que le efectuaron)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_iva_ret_le_efectuaron:
        resultado["iva"]["retenciones_iva_que_le_efectuaron"] = limpiar_monto(m_iva_ret_le_efectuaron.group(1))

    m_iva_cargo = re.search(r"(?:Impuesto a cargo|Cantidad a cargo)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_iva_cargo:
        resultado["iva"]["iva_a_cargo"] = limpiar_monto(m_iva_cargo.group(1))

    m_iva_favor = re.search(r"(?:Saldo a favor|Cantidad a favor)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_iva_favor:
        resultado["iva"]["iva_a_favor"] = limpiar_monto(m_iva_favor.group(1))

    # -------------------------------------------------------------------------
    # 3. Extracción de ISR Propio
    # -------------------------------------------------------------------------
    m_isr_ing = re.search(r"(?:Ingresos nominales del mes|Ingresos nominales|Total de ingresos facturados|Total de ingresos)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_isr_ing:
        resultado["isr"]["ingresos_nominales"] = limpiar_monto(m_isr_ing.group(1))

    m_isr_anticipos = re.search(r"(?:Anticipos de clientes recibidos|Anticipos de clientes)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_isr_anticipos:
        resultado["isr"]["anticipos_clientes"] = limpiar_monto(m_isr_anticipos.group(1))

    m_isr_tot_ing = re.search(r"(?:Total de ingresos acumulables|Ingresos acumulables)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_isr_tot_ing:
        resultado["isr"]["total_ingresos_acumulables"] = limpiar_monto(m_isr_tot_ing.group(1))

    m_isr_cargo = re.search(r"(?:ISR a cargo|Pago provisional de ISR a cargo)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_isr_cargo:
        resultado["isr"]["isr_a_cargo"] = limpiar_monto(m_isr_cargo.group(1))

    # -------------------------------------------------------------------------
    # 4. Extracción de Retenciones (Sueldos, Honorarios, Arrendamiento, etc.)
    # -------------------------------------------------------------------------
    m_ret_sueldos = re.search(r"(?:Sueldos y salarios|Por sueldos y salarios)\s*.*?Monto retenido[:\s\$]*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if not m_ret_sueldos:
        m_ret_sueldos = re.search(r"(?:ISR retenciones por salarios|Retención por salarios)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_ret_sueldos:
        resultado["retenciones"]["sueldos_y_salarios"] = limpiar_monto(m_ret_sueldos.group(1))

    m_ret_asimilados = re.search(r"(?:Asimilados a salarios|Por asimilados a salarios)\s*.*?Monto retenido[:\s\$]*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_ret_asimilados:
        resultado["retenciones"]["asimilados"] = limpiar_monto(m_ret_asimilados.group(1))

    m_ret_hon = re.search(r"(?:Servicios profesionales|Por servicios profesionales)\s*.*?Monto retenido[:\s\$]*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_ret_hon:
        resultado["retenciones"]["servicios_profesionales"] = limpiar_monto(m_ret_hon.group(1))

    m_ret_arr = re.search(r"(?:Arrendamiento de inmuebles|Por uso o goce temporal de bienes|Arrendamiento)\s*.*?Monto retenido[:\s\$]*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_ret_arr:
        resultado["retenciones"]["arrendamiento"] = limpiar_monto(m_ret_arr.group(1))

    m_ret_fletes = re.search(r"(?:Autotransporte terrestre de carga|Fletes|Servicios de autotransporte)\s*.*?Monto retenido[:\s\$]*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_ret_fletes:
        resultado["retenciones"]["fletes"] = limpiar_monto(m_ret_fletes.group(1))

    m_ret_resico = re.search(r"(?:Régimen simplificado de confianza|RESICO)\s*.*?Monto retenido[:\s\$]*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_ret_resico:
        resultado["retenciones"]["resico_pf"] = limpiar_monto(m_ret_resico.group(1))

    m_ret_iva = re.search(r"(?:Retenciones de IVA|Total de retenciones de IVA)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_ret_iva:
        resultado["retenciones"]["retenciones_iva"] = limpiar_monto(m_ret_iva.group(1))

    # -------------------------------------------------------------------------
    # 5. Extracción de IEPS
    # -------------------------------------------------------------------------
    m_ieps_tras = re.search(r"(?:IEPS causado|IEPS trasladado)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_ieps_tras:
        resultado["ieps"]["ieps_trasladado"] = limpiar_monto(m_ieps_tras.group(1))

    m_ieps_acred = re.search(r"(?:IEPS acreditable)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_ieps_acred:
        resultado["ieps"]["ieps_acreditable"] = limpiar_monto(m_ieps_acred.group(1))

    m_total_pagar = re.search(r"(?:Total a pagar|Cantidad a pagar|Línea de captura.*?Importe a pagar)\s*[:\$]?\s*([\d,]+(?:\.\d{2})?)", texto_unificado, re.IGNORECASE)
    if m_total_pagar:
        resultado["total_a_pagar"] = limpiar_monto(m_total_pagar.group(1))

    return resultado
