#!/bin/bash
# ============================================================
# STEALERLAB - extraer-binario.sh (v4)
# Extraccion de ficheros desde Windows mediante QEMU Guest Agent.
# La integridad se comprueba comparando SHA-256 en origen y destino.
# Uso: ./extraer-binario.sh <vmid> <ruta_windows> <destino_host>
# ============================================================
set -euo pipefail
VMID="${1:?falta vmid}"; SRC="${2:?falta ruta en la VM}"; DST="${3:?falta destino}"
GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
CHUNK_CHARS=350000
TAG="$(date -u +%s%N)"
B64="C:\\Windows\\Temp\\_stealerlab_${TAG}.b64"
WORK_B64="/tmp/_stealerlab_${TAG}.b64"
mkdir -p "$(dirname "$DST")"
cleanup(){
  qm guest exec "$VMID" -- powershell.exe -Command "Remove-Item -Force '$B64' -ErrorAction SilentlyContinue" >/dev/null 2>&1 || true
  rm -f "$WORK_B64"
}
trap cleanup EXIT

json_out(){ python3 -c "import sys,json; print(json.load(sys.stdin).get('out-data','').strip())"; }

echo "Extrayendo $SRC de VM $VMID (Windows, QEMU Guest Agent)..."
SRC_HASH=$(qm guest exec "$VMID" -- powershell.exe -Command "(Get-FileHash -Algorithm SHA256 -LiteralPath '$SRC').Hash" 2>/dev/null | json_out)
if ! [[ "$SRC_HASH" =~ ^[A-Fa-f0-9]{64}$ ]]; then echo -e "${RED}[FAIL] No se pudo obtener SHA-256 de origen${NC}"; exit 1; fi
SRC_HASH="$(echo "$SRC_HASH" | tr '[:upper:]' '[:lower:]')"
echo "    sha256 origen:  $SRC_HASH"

qm guest exec "$VMID" -- powershell.exe -Command "[Convert]::ToBase64String([IO.File]::ReadAllBytes('$SRC')) | Set-Content -Path '$B64' -Encoding ascii" >/dev/null 2>&1
LEN=$(qm guest exec "$VMID" -- powershell.exe -Command "(Get-Item '$B64').Length" 2>/dev/null | json_out)
[[ "$LEN" =~ ^[0-9]+$ && "$LEN" -gt 0 ]] || { echo -e "${RED}[FAIL] Base64 no generado${NC}"; exit 1; }

: > "$WORK_B64"
OFFSET=0
echo -n "    leyendo ($LEN caracteres): "
while [ "$OFFSET" -lt "$LEN" ]; do
  CHUNK=$(qm guest exec "$VMID" -- powershell.exe -Command "\$c=Get-Content -Raw '$B64'; \$n=[Math]::Min($CHUNK_CHARS, \$c.Length-$OFFSET); \$c.Substring($OFFSET,\$n)" 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin).get('out-data',''),end='')")
  [ -n "$CHUNK" ] || { echo -e "\n${RED}[FAIL] Fragmento vacio en offset $OFFSET${NC}"; exit 1; }
  printf '%s' "$CHUNK" | tr -d '\r\n' >> "$WORK_B64"
  OFFSET=$((OFFSET + CHUNK_CHARS)); echo -n "."
done
echo ""

base64 -d "$WORK_B64" > "$DST"
DST_HASH="$(sha256sum "$DST" | awk '{print $1}')"
echo "    sha256 destino: $DST_HASH"
if [ "$SRC_HASH" != "$DST_HASH" ]; then
  echo -e "${RED}[FAIL] INTEGRIDAD: hash de origen y destino NO coincide${NC}"
  rm -f "$DST"; exit 1
fi
echo -e "${GREEN}[PASS] Integridad verificada: origen == destino${NC}"
echo -e "    bytes: $(stat -c%s "$DST")"
