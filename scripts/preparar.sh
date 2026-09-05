#!/bin/bash
# ============================================================
# STEALERLAB - preparar.sh  (v9)
# v9: RealTimeIsUniversal en golden resuelve la hora de la victima.
#     [3b] ya solo sincroniza el sinkhole (la victima queda bien sola).
# Uso:  ./preparar.sh <sha256> <familia>
# ============================================================
set -euo pipefail
VICTIM=120; REMNUX=110; SINK=100
GOLDEN="golden-detonacion"
REMNUX_IP="10.10.20.10"
SINK_MGMT_IP="10.10.99.2"
SAMPLES_REMOTE="/opt/lab/muestras-cifradas"
STAGE_HOST="/root/stealerlab-final/stage"
CAPSCRIPT="/root/stealerlab-final/scripts/captura.sh"
ISO="/var/lib/vz/template/iso/muestra-actual.iso"
ZIPPASS="infected"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'

if [ $# -lt 2 ]; then echo "Uso: $0 <sha256> <familia>"; exit 1; fi
SHA="$1"; FAMILIA="$2"
TS=$(date -u +%Y%m%d-%H%M%S)
CASO="${FAMILIA}_${SHA:0:12}_${TS}"

echo -e "${CYAN}=== PREPARANDO: ${FAMILIA} (${SHA:0:16}...) ===${NC}"
echo -e "${CYAN}Caso: ${CASO}  (timestamps en UTC)${NC}"

echo -e "${CYAN}[1/7] Extrayendo binario con 7z en REMnux...${NC}"
# Extraer el ZIP (sin seleccionar aun el fichero)
ssh lab@$REMNUX_IP "rm -rf /tmp/det && mkdir -p /tmp/det && 7z x -y -p${ZIPPASS} ${SAMPLES_REMOTE}/${SHA}.zip -o/tmp/det/ >/dev/null 2>&1"

# CORRECCION (2.1 seleccion determinista): identificar el payload por su SHA-256,
# no por 'ls | head -1'. Se busca en el contenido extraido el fichero cuyo hash
# coincide EXACTAMENTE con el SHA solicitado como parametro.
EXTRACT=$(ssh lab@$REMNUX_IP "cd /tmp/det && for f in \$(find . -type f); do h=\$(sha256sum \"\$f\" | cut -d' ' -f1); if [ \"\$h\" = \"${SHA}\" ]; then basename \"\$f\"; break; fi; done")
if [ -z "$EXTRACT" ]; then
  echo -e "    ${RED}[!] Ningun fichero extraido coincide con el SHA-256 solicitado. ABORTANDO.${NC}"
  echo -e "    ${YELLOW}    Contenido del ZIP:${NC}"
  ssh lab@$REMNUX_IP "cd /tmp/det && for f in \$(find . -type f); do echo \"      \$(sha256sum \"\$f\")\"; done"
  exit 1
fi
echo -e "    ${GREEN}payload identificado por hash: ${EXTRACT}${NC}"

# CORRECCION (2.2 integridad tras scp): calcular SHA en origen (REMnux) y en destino (host)
SHA_ORIGEN=$(ssh lab@$REMNUX_IP "sha256sum /tmp/det/${EXTRACT} | cut -d' ' -f1")
mkdir -p "$STAGE_HOST"
scp -q lab@${REMNUX_IP}:/tmp/det/${EXTRACT} "${STAGE_HOST}/muestra.exe" 2>/dev/null
SHA_STAGE=$(sha256sum "${STAGE_HOST}/muestra.exe" | cut -d' ' -f1)

echo -e "    SHA esperado : ${SHA}"
echo -e "    SHA origen   : ${SHA_ORIGEN}"
echo -e "    SHA stage    : ${SHA_STAGE}"
if [ "$SHA" = "$SHA_ORIGEN" ] && [ "$SHA_ORIGEN" = "$SHA_STAGE" ]; then
  echo -e "    ${GREEN}INTEGRIDAD   : OK (${SHA:0:16}...)${NC}"
else
  echo -e "    ${RED}INTEGRIDAD   : FALLO - los hashes no coinciden. ABORTANDO.${NC}"
  exit 1
fi
echo -e "    ${GREEN}binario en host: $(( $(stat -c%s "${STAGE_HOST}/muestra.exe")/1024 )) KB${NC}"

echo -e "${CYAN}[2/7] Revirtiendo victima a ${GOLDEN}...${NC}"
qm rollback $VICTIM $GOLDEN && sleep 3

echo -e "${CYAN}[3/7] Arrancando victima...${NC}"
qm start $VICTIM
echo -n "    esperando guest agent"
QGA_OK=0
for i in $(seq 1 30); do
  if qm agent $VICTIM ping >/dev/null 2>&1; then echo -e " ${GREEN}OK${NC}"; QGA_OK=1; break; fi
  echo -n "."; sleep 3
done
# CORRECCION (bloqueo 2): abortar si el agente QEMU no responde (no detonar sin QGA)
if [ "$QGA_OK" -ne 1 ]; then
  echo -e "\n    ${RED}[!] El agente QEMU no responde tras 30 intentos. ABORTANDO.${NC}"
  echo -e "    ${RED}    No se puede extraer evidencia sin QGA; no se detona.${NC}"
  exit 1
fi

echo -e "${CYAN}[3b] Sincronizando reloj del sinkhole a UTC...${NC}"
qm guest exec $SINK -- date -u -s "$(date -u '+%Y-%m-%d %H:%M:%S')" >/dev/null 2>&1
# La victima tiene RealTimeIsUniversal=1: su hora ya es correcta, no se toca.
# CORRECCION (bug tiempo): comparar fecha COMPLETA y calcular offset, no solo HH:mm:ss
VUTC=$(qm guest exec $VICTIM -- powershell.exe -Command "[DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')" 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin).get('out-data','').strip())" 2>/dev/null)
HOSTUTC=$(date -u '+%Y-%m-%d %H:%M:%S')
# Calcular offset en segundos entre victima y host
OFFSET=$(python3 -c "from datetime import datetime as d; a=d.strptime('$VUTC','%Y-%m-%d %H:%M:%S'); b=d.strptime('$HOSTUTC','%Y-%m-%d %H:%M:%S'); print(abs(int((a-b).total_seconds())))" 2>/dev/null || echo 9999)
echo -e "    ${GREEN}victima UTC=${VUTC} | host UTC=${HOSTUTC} | offset=${OFFSET}s${NC}"
if [ "$OFFSET" -gt 5 ]; then
  echo -e "    ${RED}[!] AVISO: offset de reloj > 5s. La correlacion temporal puede fallar.${NC}"
  echo -e "    ${YELLOW}Revisa la sincronizacion antes de detonar (rollback puede haber cambiado la fecha).${NC}"
fi

echo -e "${CYAN}[4/7] Iniciando captura en el sinkhole (ens18)...${NC}"
RES=$(${CAPSCRIPT} start ${CASO})
echo "    $RES"
# CORRECCION (bloqueo 3): si la captura no arranca de forma inequivoca, ABORTAR la detonacion.
if [[ "$RES" == *captura-activa* ]]; then
  echo -e "    ${GREEN}OK${NC}"
else
  echo -e "    ${RED}[!] La captura no arranco de forma inequivoca. ABORTANDO detonacion.${NC}"
  echo -e "    ${RED}    Revisa captura.sh / sinkhole antes de detonar. La victima NO se detona.${NC}"
  exit 1
fi

echo -e "${CYAN}[5/7] Rotando log TLS del sinkhole...${NC}"
ssh -o StrictHostKeyChecking=no lab@$SINK_MGMT_IP "truncate -s 0 /var/log/mitm/mitmdump.log" 2>/dev/null \
  && echo -e "    ${GREEN}mitmdump.log limpio${NC}" || echo -e "    ${YELLOW}[!] revisar${NC}"

echo -e "${CYAN}[6/7] Montando binario como ISO (ide2)...${NC}"
WORK="${STAGE_HOST}/iso-muestra"
rm -rf "$WORK"; mkdir -p "$WORK"
cp "${STAGE_HOST}/muestra.exe" "$WORK/muestra.exe"
genisoimage -quiet -o "$ISO" -J -R -V "MUESTRA" "$WORK/" 2>/dev/null \
  || xorriso -as mkisofs -quiet -o "$ISO" -J -R -V "MUESTRA" "$WORK/" 2>/dev/null
qm set $VICTIM --ide2 "local:iso/muestra-actual.iso,media=cdrom" >/dev/null 2>&1
sleep 3
LETRA=$(qm guest exec $VICTIM -- powershell.exe -Command "(Get-CimInstance Win32_LogicalDisk | Where-Object VolumeName -eq 'MUESTRA').DeviceID" 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin).get('out-data','').strip())" 2>/dev/null)
[ -n "$LETRA" ] && echo -e "    ${GREEN}muestra en ${LETRA}${NC}" || echo -e "    ${YELLOW}[!] verificar unidad${NC}"

echo -e "${CYAN}[7/7] Registrando caso...${NC}"
echo "$CASO" > /tmp/caso_actual.txt
ssh lab@$REMNUX_IP "echo '${CASO}|${SHA}|${FAMILIA}|$(date -u +%FT%TZ)' >> /opt/lab/reports/casos.log" 2>/dev/null
echo -e "    ${GREEN}registrado${NC}"

echo ""
echo -e "${GREEN}=== ENTORNO LISTO (relojes UTC correctos) ===${NC}"
echo -e "${YELLOW}EN LA CONSOLA VNC DE LA VICTIMA:${NC}"
echo "  1. mkdir C:\\muestra -Force   (si no existe)"
echo "  2. Copy-Item ${LETRA:-E:}\\muestra.exe C:\\muestra\\muestra.exe"
echo "  3. Start-Process C:\\muestra\\muestra.exe   y OBSERVA durante 15 minutos"
echo "  4. Al terminar, en el host: ./recoger.sh"
echo -e "Caso: ${CASO}"
