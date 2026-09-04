#!/bin/bash
# ============================================================
# STEALERLAB - montar-muestra.sh
# Crea un ISO con la muestra y lo monta en la victima (solo lectura).
# Uso: ./montar-muestra.sh <vmid> <ruta_zip_en_host>
# ============================================================
set -euo pipefail
VMID="${1:?falta vmid}"; ZIP="${2:?falta ruta zip}"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
if [ ! -f "$ZIP" ]; then echo -e "${RED}No existe $ZIP${NC}"; exit 1; fi
WORK="/root/lab/stage/iso-muestra"
ISO="/var/lib/vz/template/iso/muestra-actual.iso"
echo -e "${CYAN}[1/3] Construyendo ISO con la muestra...${NC}"
rm -rf "$WORK"; mkdir -p "$WORK"
cp "$ZIP" "$WORK/"
genisoimage -quiet -o "$ISO" -J -R -V "MUESTRA" "$WORK/" 2>/dev/null \
  || xorriso -as mkisofs -quiet -o "$ISO" -J -R -V "MUESTRA" "$WORK/" 2>/dev/null
echo -e "    ${GREEN}ISO creado: $(basename $ISO)${NC}"
echo -e "${CYAN}[2/3] Montando ISO en la victima (sata1)...${NC}"
qm set $VMID --sata1 "local:iso/muestra-actual.iso,media=cdrom" >/dev/null 2>&1
sleep 3
echo -e "    ${GREEN}ISO montado${NC}"
echo -e "${CYAN}[3/3] Localizando unidad en Windows...${NC}"
LETRA=$(qm guest exec $VMID -- powershell.exe -Command \
  "(Get-Volume | Where-Object {\$_.FileSystemLabel -eq 'MUESTRA'} | Select -First 1).DriveLetter" 2>/dev/null \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('out-data','').strip())" 2>/dev/null)
echo ""
if [ -n "$LETRA" ]; then
  echo -e "${GREEN}=== MUESTRA MONTADA en ${LETRA}: ===${NC}"
  echo "  1. Abre ${LETRA}:\\  (contiene el ZIP)"
  echo "  2. Copia el ZIP a C:\\muestra\\  y extrae (password: infected)"
  echo "  3. Detona desde C:\\muestra\\"
else
  echo -e "${YELLOW}=== ISO montado, revisa las unidades en la victima ===${NC}"
fi
echo -e "${CYAN}Para desmontar: qm set ${VMID} --delete sata1${NC}"
