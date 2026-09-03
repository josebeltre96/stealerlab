#!/bin/bash
# ============================================================
# STEALERLAB - preparar.sh  (v9)
# v9: RealTimeIsUniversal en golden resuelve la hora de la victima.
#     [3b] ya solo sincroniza el sinkhole (la victima queda bien sola).
# Uso:  ./preparar.sh <sha256> <familia>
# ============================================================
set -u
VICTIM=120; REMNUX=110; SINK=100
GOLDEN="golden-detonacion"
REMNUX_IP="10.10.20.10"
SINK_MGMT_IP="10.10.99.2"
REMNUX_CAP_IF="cap0"
SAMPLES_REMOTE="/opt/lab/muestras-cifradas"
STAGE_HOST="/root/lab/stage"
CAPSCRIPT="/opt/lab/scripts/captura.sh"
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
EXTRACT=$(ssh lab@$REMNUX_IP "rm -rf /tmp/det && mkdir -p /tmp/det && 7z x -y -p${ZIPPASS} ${SAMPLES_REMOTE}/${SHA}.zip -o/tmp/det/ >/dev/null 2>&1 && ls /tmp/det/ | head -1")
if [ -z "$EXTRACT" ]; then echo -e "    ${RED}[!] Fallo al extraer${NC}"; exit 1; fi
echo -e "    ${GREEN}extraido: ${EXTRACT}${NC}"
mkdir -p "$STAGE_HOST"
scp -q lab@${REMNUX_IP}:/tmp/det/${EXTRACT} "${STAGE_HOST}/muestra.exe" 2>/dev/null
echo -e "    ${GREEN}binario en host: $(( $(stat -c%s "${STAGE_HOST}/muestra.exe")/1024 )) KB${NC}"

echo -e "${CYAN}[2/7] Revirtiendo victima a ${GOLDEN}...${NC}"
qm rollback $VICTIM $GOLDEN && sleep 3

echo -e "${CYAN}[3/7] Arrancando victima...${NC}"
qm start $VICTIM
echo -n "    esperando guest agent"
for i in $(seq 1 30); do
  if qm agent $VICTIM ping >/dev/null 2>&1; then echo -e " ${GREEN}OK${NC}"; break; fi
  echo -n "."; sleep 3
done

echo -e "${CYAN}[3b] Sincronizando reloj del sinkhole a UTC...${NC}"
qm guest exec $SINK -- date -u -s "$(date -u '+%Y-%m-%d %H:%M:%S')" >/dev/null 2>&1
# La victima tiene RealTimeIsUniversal=1: su hora ya es correcta, no se toca.
VUTC=$(qm guest exec $VICTIM -- powershell.exe -Command "[DateTime]::UtcNow.ToString('HH:mm:ss')" 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin).get('out-data','').strip())" 2>/dev/null)
echo -e "    ${GREEN}sinkhole sincronizado | victima UTC=${VUTC} (host UTC=$(date -u '+%H:%M:%S'))${NC}"

echo -e "${CYAN}[4/7] Iniciando captura en REMnux (${REMNUX_CAP_IF})...${NC}"
RES=$(ssh lab@$REMNUX_IP "sudo ${CAPSCRIPT} start ${CASO} ${REMNUX_CAP_IF}")
echo "    $RES"
[[ "$RES" == captura-activa* ]] && echo -e "    ${GREEN}OK${NC}" || echo -e "    ${YELLOW}[!] revisar${NC}"

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
echo "  3. Start-Process C:\\muestra\\muestra.exe   y OBSERVA 5-10 min"
echo "  4. Al terminar, en el host: ./recoger.sh"
echo -e "Caso: ${CASO}"
