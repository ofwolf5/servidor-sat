import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger("conciliador_sat")

# Namespaces estándar CFDI 3.3, 4.0, Pagos 1.0, Pagos 2.0 y Nómina 1.2
NS = {
    "cfdi": "http://www.sat.gob.mx/cfd/4",
    "cfdi33": "http://www.sat.gob.mx/cfd/3",
    "pago10": "http://www.sat.gob.mx/Pagos",
    "pago20": "http://www.sat.gob.mx/Pagos20",
    "nomina12": "http://www.sat.gob.mx/nomina12"
}

def a_float(valor: Any) -> float:
    try:
        return float(valor) if valor is not None else 0.0
    except (ValueError, TypeError):
        return 0.0

def parse_fecha(fecha_str: str) -> Optional[datetime]:
    if not fecha_str:
        return None
    limpia = fecha_str.strip().split("T")[0]
    try:
        return datetime.strptime(limpia, "%Y-%m-%d")
    except Exception:
        return None

def limpiar_tag(tag: str) -> str:
    """Remueve namespaces tipo {http://...}Tag."""
    return tag.split("}")[-1] if "}" in tag else tag

# ---------------------------------------------------------------------------
# Extractor granular de XML de CFDI
# ---------------------------------------------------------------------------

def procesar_xml_cfdi(xml_str: str, rfc_empresa: str) -> Dict[str, Any]:
    """
    Analiza un CFDI individual (Ingreso, Egreso, Pago o Nómina) y desglosa
    sus montos según si fue Emitido o Recibido, PUE o CRP.
    """
    res = {
        "es_emitido": False,
        "es_recibido": False,
        "tipo_comprobante": "",
        "metodo_pago": "",
        "fecha": None,
        "subtotal": 0.0,
        "anticipos": 0.0,
        "iva_16": 0.0,
        "iva_8": 0.0,
        "ret_isr_sueldos": 0.0,
        "ret_isr_servicios": 0.0,
        "ret_isr_arrendamiento": 0.0,
        "ret_isr_fletes": 0.0,
        "ret_isr_resico": 0.0,
        "ret_iva": 0.0,
        "ieps": 0.0,
        # Para complementos de pago (CRP)
        "crp_pagos": []
    }

    try:
        root = ET.fromstring(xml_str.encode("utf-8") if isinstance(xml_str, str) else xml_str)
    except Exception as e:
        logger.warning(f"Error parseando XML: {e}")
        return res

    tipo = root.attrib.get("TipoDeComprobante", "I").upper()
    metodo = root.attrib.get("MetodoPago", "").upper()
    fecha = parse_fecha(root.attrib.get("Fecha", ""))
    subtotal = a_float(root.attrib.get("SubTotal", 0.0))

    emisor_elem = next((e for e in root if limpiar_tag(e.tag) == "Emisor"), None)
    receptor_elem = next((e for e in root if limpiar_tag(e.tag) == "Receptor"), None)

    rfc_emisor = (emisor_elem.attrib.get("Rfc", "") if emisor_elem is not None else "").upper().strip()
    rfc_receptor = (receptor_elem.attrib.get("Rfc", "") if receptor_elem is not None else "").upper().strip()
    rfc_emp = rfc_empresa.upper().strip()

    es_emitido = (rfc_emisor == rfc_emp)
    es_recibido = (rfc_receptor == rfc_emp)

    res.update({
        "es_emitido": es_emitido,
        "es_recibido": es_recibido,
        "tipo_comprobante": tipo,
        "metodo_pago": metodo,
        "fecha": fecha,
        "subtotal": subtotal
    })

    # 1. Facturas de Nómina (Retención de ISR Sueldos)
    if tipo == "N":
        for elem in root.iter():
            t = limpiar_tag(elem.tag)
            if t == "Deduccion":
                # Clave 002 = ISR retenido por sueldos/salarios
                c_tipo = elem.attrib.get("TipoDeduccion", "")
                if c_tipo == "002":
                    res["ret_isr_sueldos"] += a_float(elem.attrib.get("Importe", 0.0))
        return res

    # 2. Facturas de Ingreso / Egreso (PUE y PPD)
    if tipo in ("I", "E"):
        # Revisar si hay anticipos de clientes (Clave 84111506)
        for elem in root.iter():
            if limpiar_tag(elem.tag) == "Concepto":
                c_prod = elem.attrib.get("ClaveProdServ", "")
                if c_prod == "84111506":
                    res["anticipos"] += a_float(elem.attrib.get("Importe", 0.0))

            # Impuestos Trasladados
            elif limpiar_tag(elem.tag) == "Traslado":
                imp = elem.attrib.get("Impuesto", "")
                tasa = a_float(elem.attrib.get("TasaOCuota", 0.0))
                monto = a_float(elem.attrib.get("Importe", 0.0))
                if imp == "002":  # IVA
                    if 0.15 <= tasa <= 0.17:
                        res["iva_16"] += monto
                    elif 0.07 <= tasa <= 0.09:
                        res["iva_8"] += monto
                elif imp == "003":  # IEPS
                    res["ieps"] += monto

            # Impuestos Retenidos
            elif limpiar_tag(elem.tag) == "Retencion":
                imp = elem.attrib.get("Impuesto", "")
                monto = a_float(elem.attrib.get("Importe", 0.0))
                tasa = a_float(elem.attrib.get("TasaOCuota", 0.0))

                if imp == "002":  # Retención de IVA
                    res["ret_iva"] += monto
                elif imp == "001":  # Retención de ISR
                    # Clasificación por tasa típica: 10% honorarios/arrendamiento, 1.25% RESICO
                    if 0.099 <= tasa <= 0.1067:
                        res["ret_isr_servicios"] += monto
                    elif 0.012 <= tasa <= 0.013:
                        res["ret_isr_resico"] += monto
                    else:
                        res["ret_isr_arrendamiento"] += monto

    # 3. Complementos de Recepción de Pagos (CRP)
    elif tipo == "P":
        for elem in root.iter():
            if limpiar_tag(elem.tag) == "Pago":
                f_pago = parse_fecha(elem.attrib.get("FechaPago", ""))
                monto_pago = a_float(elem.attrib.get("Monto", 0.0))
                
                # Desglose en Pagos 2.0 (nodo ImpuestosP o ImpuestosDR)
                iva_pago = 0.0
                ret_isr_pago = 0.0
                ret_iva_pago = 0.0

                for sub in elem.iter():
                    st = limpiar_tag(sub.tag)
                    if st in ("TrasladoP", "TrasladoDR"):
                        if sub.attrib.get("ImpuestoP", sub.attrib.get("Impuesto", "")) == "002":
                            iva_pago += a_float(sub.attrib.get("ImporteP", sub.attrib.get("Importe", 0.0)))
                    elif st in ("RetencionP", "RetencionDR"):
                        imp = sub.attrib.get("ImpuestoP", sub.attrib.get("Impuesto", ""))
                        m = a_float(sub.attrib.get("ImporteP", sub.attrib.get("Importe", 0.0)))
                        if imp == "001":
                            ret_isr_pago += m
                        elif imp == "002":
                            ret_iva_pago += m

                res["crp_pagos"].append({
                    "fecha_pago": f_pago,
                    "monto_total": monto_pago,
                    "iva_16": iva_pago,
                    "ret_isr": ret_isr_pago,
                    "ret_iva": ret_iva_pago
                })

    return res

# ---------------------------------------------------------------------------
# Motor de Conciliación: Declarado vs CFDI
# ---------------------------------------------------------------------------

def conciliar_periodo(
    datos_declaracion: Dict[str, Any],
    lista_xmls_comprobantes: List[str]
) -> Dict[str, Any]:
    """
    Cruza los datos de la declaración contra los CFDI del periodo respetando:
    1. Flujo de Efectivo (PUE con fecha del mes + CRP con FechaPago del mes).
    2. Devengado para ISR (Subtotal emitidos PUE + PPD del mes + Anticipos).
    """
    metadatos = datos_declaracion.get("metadatos", {})
    rfc_empresa = metadatos.get("rfc", "").strip().upper()
    ejercicio = metadatos.get("ejercicio")
    
    # Mapeo de nombre de mes a número entero
    meses_map = {
        "enero": 1, "febrero": 2, "marzo": 3, "abril": 4, "mayo": 5, "junio": 6,
        "julio": 7, "agosto": 8, "septiembre": 9, "octubre": 10, "noviembre": 11, "diciembre": 12
    }
    periodo_str = metadatos.get("periodo", "").lower().strip()
    mes_num = meses_map.get(periodo_str, datetime.now().month)

    # Acumuladores CFDI
    cfdi_det = {
        "isr_ingresos_nominales": 0.0,
        "isr_anticipos": 0.0,
        "iva_trasladado_pue": 0.0,
        "iva_trasladado_crp": 0.0,
        "iva_acreditable_pue": 0.0,
        "iva_acreditable_crp": 0.0,
        "ret_iva_efectuada_a_terceros": 0.0,
        "ret_isr_sueldos": 0.0,
        "ret_isr_servicios": 0.0,
        "ret_isr_arrendamiento": 0.0,
        "ret_isr_resico": 0.0,
        "ieps_trasladado": 0.0,
        "ieps_acreditable": 0.0
    }

    # Procesar cada XML
    for xml_raw in lista_xmls_comprobantes:
        info = procesar_xml_cfdi(xml_raw, rfc_empresa)
        f = info["fecha"]

        # -------------------------------------------------------------
        # 1. INGRESOS ISR (Devengado: Facturas emitidas con fecha del mes)
        # -------------------------------------------------------------
        if info["es_emitido"] and info["tipo_comprobante"] == "I":
            if f and f.year == ejercicio and f.month == mes_num:
                cfdi_det["isr_ingresos_nominales"] += info["subtotal"]
                cfdi_det["isr_anticipos"] += info["anticipos"]

        # -------------------------------------------------------------
        # 2. IVA Y RETENCIONES - FACTURAS PUE (Flujo de efectivo inmediato)
        # -------------------------------------------------------------
        if f and f.year == ejercicio and f.month == mes_num and info["metodo_pago"] == "PUE":
            if info["es_emitido"]:
                cfdi_det["iva_trasladado_pue"] += (info["iva_16"] + info["iva_8"])
                cfdi_det["ieps_trasladado"] += info["ieps"]
            elif info["es_recibido"]:
                cfdi_det["iva_acreditable_pue"] += (info["iva_16"] + info["iva_8"])
                cfdi_det["ieps_acreditable"] += info["ieps"]
                cfdi_det["ret_iva_efectuada_a_terceros"] += info["ret_iva"]
                cfdi_det["ret_isr_servicios"] += info["ret_isr_servicios"]
                cfdi_det["ret_isr_arrendamiento"] += info["ret_isr_arrendamiento"]
                cfdi_det["ret_isr_resico"] += info["ret_isr_resico"]

        # -------------------------------------------------------------
        # 3. NÓMINA (Retenciones por Salarios con Fecha en el mes)
        # -------------------------------------------------------------
        if info["es_emitido"] and info["tipo_comprobante"] == "N":
            if f and f.year == ejercicio and f.month == mes_num:
                cfdi_det["ret_isr_sueldos"] += info["ret_isr_sueldos"]

        # -------------------------------------------------------------
        # 4. COMPLEMENTOS DE RECEPCIÓN DE PAGO (FechaPago dentro del mes)
        # -------------------------------------------------------------
        if info["tipo_comprobante"] == "P":
            for p in info["crp_pagos"]:
                fp = p["fecha_pago"]
                if fp and fp.year == ejercicio and fp.month == mes_num:
                    if info["es_emitido"]:
                        cfdi_det["iva_trasladado_crp"] += p["iva_16"]
                    elif info["es_recibido"]:
                        cfdi_det["iva_acreditable_crp"] += p["iva_16"]
                        cfdi_det["ret_iva_efectuada_a_terceros"] += p["ret_iva"]

    # Totales acumulados
    tot_iva_trasladado_cfdi = cfdi_det["iva_trasladado_pue"] + cfdi_det["iva_trasladado_crp"]
    tot_iva_acreditable_cfdi = cfdi_det["iva_acreditable_pue"] + cfdi_det["iva_acreditable_crp"]
    tot_ingresos_isr_cfdi = cfdi_det["isr_ingresos_nominales"] + cfdi_det["isr_anticipos"]
    tot_ret_terceros_isr_cfdi = (
        cfdi_det["ret_isr_servicios"] +
        cfdi_det["ret_isr_arrendamiento"] +
        cfdi_det["ret_isr_resico"]
    )

    # Datos declarados
    dec_iva = datos_declaracion.get("iva", {})
    dec_isr = datos_declaracion.get("isr", {})
    dec_ret = datos_declaracion.get("retenciones", {})

    dec_iva_tras = dec_iva.get("iva_trasladado_cobrado", 0.0)
    dec_iva_acred = dec_iva.get("iva_acreditable_pagado", 0.0)
    dec_isr_ing = dec_isr.get("ingresos_nominales", 0.0)
    dec_ret_sueldos = dec_ret.get("sueldos_y_salarios", 0.0)
    dec_ret_terceros = (
        dec_ret.get("servicios_profesionales", 0.0) +
        dec_ret.get("arrendamiento", 0.0) +
        dec_ret.get("resico_pf", 0.0)
    )
    dec_ret_iva = dec_ret.get("retenciones_iva", 0.0)

    # -------------------------------------------------------------------------
    # Comparativas y Semáforo
    # -------------------------------------------------------------------------
    def evaluar_diferencia(declarado: float, cfdi: float, tipo: str = "ingreso") -> Dict[str, Any]:
        dif = round(declarado - cfdi, 2)
        # Tolerancia normal de redondeo de centavos
        if abs(dif) <= 5.0:
            return {"declarado": declarado, "cfdi": round(cfdi, 2), "diferencia": 0.0, "estatus": "CORRECTO", "color": "verde"}
        
        # En ingresos y retenciones, declarar MENOS de lo timbrado enerva cartas invitación (Riesgo Alto)
        if tipo in ("ingreso", "retencion") and dif < -5.0:
            return {"declarado": declarado, "cfdi": round(cfdi, 2), "diferencia": dif, "estatus": "RIESGO_ALTO", "color": "rojo"}
        
        # En IVA acreditable, declarar MÁS de lo timbrado/pagado enerva rechazos (Riesgo Alto)
        if tipo == "acreditable" and dif > 5.0:
            return {"declarado": declarado, "cfdi": round(cfdi, 2), "diferencia": dif, "estatus": "RIESGO_ALTO", "color": "rojo"}

        return {"declarado": declarado, "cfdi": round(cfdi, 2), "diferencia": dif, "estatus": "OBSERVACION", "color": "amarillo"}

    return {
        "periodo": f"{periodo_str.capitalize()} {ejercicio}",
        "rfc": rfc_empresa,
        "resumen_conciliacion": {
            "iva_trasladado": evaluar_diferencia(dec_iva_tras, tot_iva_trasladado_cfdi, "ingreso"),
            "iva_acreditable": evaluar_diferencia(dec_iva_acred, tot_iva_acreditable_cfdi, "acreditable"),
            "isr_ingresos_nominales": evaluar_diferencia(dec_isr_ing, tot_ingresos_isr_cfdi, "ingreso"),
            "retenciones_sueldos_salarios": evaluar_diferencia(dec_ret_sueldos, cfdi_det["ret_isr_sueldos"], "retencion"),
            "retenciones_terceros_isr": evaluar_diferencia(dec_ret_terceros, tot_ret_terceros_isr_cfdi, "retencion"),
            "retenciones_iva_a_terceros": evaluar_diferencia(dec_ret_iva, cfdi_det["ret_iva_efectuada_a_terceros"], "retencion")
        },
        "desglose_cfdi_determinado": cfdi_det
    }
