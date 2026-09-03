#!/bin/bash
# ============================================================
# STEALERLAB - recoger.sh  (v9)
# v9: FilterHashtable (rapido, sin timeout) + evtx completo respaldo +
#     verificacion de contenido + secuencia correcta (extrae ANTES de revertir).
# Uso:  ./recoger.sh   |   ./recoger.sh <caso>
# ============================================================
set -u
VICTIM=120; REMNUX=110; SINK=100
GOLDEN="golden-detonacion"
REMNUX_IP="10.10.20.10"
SINK_MGMT_IP="10.10.99.2"
ZEEK="/opt/zeek/bin/zeek"
CAPSCRIPT="/opt/lab/scripts/captura.sh"
EXTRACTOR="/root/lab/extraer-binario.sh"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; RED='\033[0;31m'; NC='\033[0m'

CASO="${1:-$(cat /tmp/caso_actual.txt 2>/dev/null)}"
if [ -z "$CASO" ]; then echo "No hay caso actual. Uso: $0 <caso>"; exit 1; fi
DIR="/opt/lab/reports/${CASO}"
PCAPDIR="/opt/lab/pcap/${CASO}"
FAM=$(echo "$CASO" | cut -d_ -f1)
SNAP="f-${FAM:0:20}-$(date -u +%y%m%d-%H%M)"

echo -e "${CYAN}=== RECOGIENDO: ${CASO} ===${NC}"
echo -e "${CYAN}    snapshot forense: ${SNAP}${NC}"
ssh lab@$REMNUX_IP "mkdir -p ${DIR}"
mkdir -p /root/lab/stage

# ------------------------------------------------------------
# TELEMETRIA SYSMON  (se extrae de la VICTIMA INFECTADA VIVA, antes de revertir)
# ------------------------------------------------------------

# 1. Generar resumen legible con FilterHashtable (rapido, filtra en el motor)
echo -e "${CYAN}[1/8] Generando resumen Sysmon en la victima (FilterHashtable)...${NC}"
qm guest exec $VICTIM -- powershell.exe -Command \
  "\$o='C:\sysmon_resumen.txt'; Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1,3,11,22} -ErrorAction SilentlyContinue | Sort-Object TimeCreated | ForEach-Object { \$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')+' [Id'+\$_.Id+'] '+((\$_.Message -split \"\`n\")[0]) + ' :: ' + ((\$_.Message -split \"\`n\" | Select-String 'Image:|QueryName:|DestinationIp:|DestinationPort:|DestinationHostname:|TargetFilename:|CommandLine:') -join ' | ') } | Out-File \$o -Encoding UTF8; (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1,3,11,22} -ErrorAction SilentlyContinue).Count" >/dev/null 2>&1

# 2. Traer el resumen (texto, lectura directa)
echo -e "${CYAN}[2/8] Recuperando resumen a REMnux...${NC}"
qm guest exec $VICTIM -- powershell.exe -Command "Get-Content -Raw C:\sysmon_resumen.txt" 2>/dev/null \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('out-data',''))" > /root/lab/stage/sysmon_resumen.txt 2>/dev/null
NLINEAS=$(wc -l < /root/lab/stage/sysmon_resumen.txt 2>/dev/null || echo 0)
if [ "${NLINEAS:-0}" -gt 5 ]; then
  scp -q /root/lab/stage/sysmon_resumen.txt lab@$REMNUX_IP:${DIR}/sysmon_resumen.txt
  echo -e "    ${GREEN}sysmon_resumen.txt (${NLINEAS} eventos clave)${NC}"
else
  echo -e "    ${RED}[!] resumen con solo ${NLINEAS} lineas - REVISAR antes de revertir${NC}"
fi

# 3. Exportar evtx completo y extraerlo (respaldo binario integro)
echo -e "${CYAN}[3/8] Exportando evtx completo (respaldo)...${NC}"
qm guest exec $VICTIM -- powershell.exe -Command \
  "wevtutil epl 'Microsoft-Windows-Sysmon/Operational' C:\sysmon.evtx /ow:true" >/dev/null 2>&1
if [ -x "$EXTRACTOR" ]; then
  $EXTRACTOR $VICTIM "C:\\sysmon.evtx" /root/lab/stage/sysmon.evtx >/dev/null 2>&1
  if [ -s /root/lab/stage/sysmon.evtx ]; then
    scp -q /root/lab/stage/sysmon.evtx lab@$REMNUX_IP:${DIR}/sysmon.evtx
    echo -e "    ${GREEN}sysmon.evtx ($(( $(stat -c%s /root/lab/stage/sysmon.evtx)/1024 )) KB) respaldado${NC}"
  else
    echo -e "    ${YELLOW}[!] evtx no extraido (queda en snapshot forense)${NC}"
  fi
fi

# 4. Distribucion de eventos en pantalla
echo -e "${CYAN}[4/8] Distribucion de eventos Sysmon:${NC}"
qm guest exec $VICTIM -- powershell.exe -Command \
  "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1,3,11,22} -ErrorAction SilentlyContinue | Group-Object Id -NoElement | Sort Count -Descending | ForEach-Object { '    Id ' + \$_.Name + ': ' + \$_.Count }" 2>/dev/null \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('out-data',''))" 2>/dev/null

# ------------------------------------------------------------
# RED
# ------------------------------------------------------------

# 5. Detener captura y procesar con Zeek (en dir escribible por lab)
echo -e "${CYAN}[5/8] Deteniendo captura y procesando con Zeek...${NC}"
ssh lab@$REMNUX_IP "sudo ${CAPSCRIPT} stop ${CASO}" 2>/dev/null
PSIZE=$(ssh lab@$REMNUX_IP "stat -c%s ${PCAPDIR}/captura.pcap 2>/dev/null || echo 0")
if [ "${PSIZE:-0}" -gt 24 ]; then
  ssh lab@$REMNUX_IP "rm -rf /tmp/zk-${CASO} && mkdir -p /tmp/zk-${CASO} && cd /tmp/zk-${CASO} && ${ZEEK} -C -r ${PCAPDIR}/captura.pcap 2>/dev/null; sudo cp /tmp/zk-${CASO}/*.log ${PCAPDIR}/ 2>/dev/null; echo -n '    logs Zeek: '; ls ${PCAPDIR}/*.log 2>/dev/null | xargs -n1 basename | tr '\n' ' '; echo"
else
  echo -e "    ${YELLOW}[!] PCAP sin datos (${PSIZE} bytes) - evidencia de red via mitmdump${NC}"
fi

# 6. Recoger mitmdump.log (EVIDENCIA TLS) por red de gestion
echo -e "${CYAN}[6/8] Recogiendo evidencia TLS (mitmdump.log) por gestion...${NC}"
LSIZE=$(ssh -o StrictHostKeyChecking=no lab@$SINK_MGMT_IP "stat -c%s /var/log/mitm/mitmdump.log 2>/dev/null || echo 0")
if [ "${LSIZE:-0}" -gt 0 ]; then
  scp -q lab@$SINK_MGMT_IP:/var/log/mitm/mitmdump.log /root/lab/stage/mitmdump.log
  scp -q /root/lab/stage/mitmdump.log lab@$REMNUX_IP:${DIR}/mitmdump.log
  echo -e "    ${GREEN}mitmdump.log (${LSIZE} bytes)${NC}"
  ssh lab@$REMNUX_IP "grep -iE 'GET |POST |CONNECT |HEAD ' ${DIR}/mitmdump.log | grep -viE 'msftconnecttest|microsoft|skype|windows|msedge|bing|digicert|verisign|windowsupdate' > ${DIR}/c2_candidatas.txt 2>/dev/null; echo -n '    peticiones no-Windows (posible C2): '; wc -l < ${DIR}/c2_candidatas.txt"
  echo -n "    C2 unicos: "
  ssh lab@$REMNUX_IP "grep -oE '(GET|POST|CONNECT|HEAD) https?://[^/: ]+' ${DIR}/c2_candidatas.txt 2>/dev/null | awk '{print \$2}' | sort -u | tr '\n' ' '"; echo
else
  echo -e "    ${YELLOW}[!] mitmdump.log vacio (sin trafico HTTP/S)${NC}"
fi

# ------------------------------------------------------------
# PRESERVACION Y RESET
# ------------------------------------------------------------

# 7. Snapshot forense (despues de extraer todo)
echo -e "${CYAN}[7/8] Snapshot forense: ${SNAP}...${NC}"
qm snapshot $VICTIM "${SNAP}" --description "Infectado: ${CASO}" 2>/dev/null \
  && echo -e "    ${GREEN}${SNAP} creado${NC}" || echo -e "    ${YELLOW}existe/error${NC}"

# 8. Desmontar ISO, apagar, revertir a golden (borrando forense para cadena limpia)
echo -e "${CYAN}[8/8] Desmontando ISO y revirtiendo a golden...${NC}"
qm set $VICTIM --ide2 none,media=cdrom >/dev/null 2>&1
qm stop $VICTIM 2>/dev/null; sleep 2
# Borrar el forense para que golden sea el mas reciente (evidencia ya en REMnux)
qm delsnapshot $VICTIM "${SNAP}" 2>/dev/null
qm rollback $VICTIM $GOLDEN 2>/dev/null && echo -e "    ${GREEN}victima en golden (forense ${SNAP} borrado; evidencia en REMnux)${NC}" \
  || echo -e "    ${YELLOW}[!] revisar rollback${NC}"

echo ""
echo -e "${GREEN}=== EVIDENCIA RECOGIDA: ${CASO} ===${NC}"
echo "  ${DIR}/sysmon_resumen.txt   (comportamiento host, ${NLINEAS} eventos)"
echo "  ${DIR}/sysmon.evtx          (telemetria completa respaldo)"
echo "  ${DIR}/mitmdump.log         (trafico TLS descifrado)"
echo "  ${DIR}/c2_candidatas.txt    (posible C2)"
echo "  ${PCAPDIR}/*.log            (Zeek: conn,dns,http,ssl,ja4)"
echo -e "${CYAN}Siguiente: ./preparar.sh <sha256> <familia>${NC}"
