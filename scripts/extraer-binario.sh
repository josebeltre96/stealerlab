#!/bin/bash
# ============================================================
# STEALERLAB - extraer-binario.sh (v3)
# Extrae un fichero de la VM victima (WINDOWS) por el agente QEMU,
# troceando el base64 para no exceder el buffer del guest agent.
#
# CORRECCION (v3): la victima es Windows 10, por lo que la codificacion
# se realiza con PowerShell (no con bash/base64/split de Unix, que no
# existen en Windows). El reensamblado y la decodificacion se hacen en
# el host Linux.
#
# Uso: ./extraer-binario.sh <vmid> <ruta_en_vm_windows> <destino_host>
#   ej: ./extraer-binario.sh 120 'C:\muestra\muestra.exe' /opt/lab/out/muestra.exe
# ============================================================
set -euo pipefail

VMID="${1:?falta vmid}"; SRC="${2:?falta ruta en la VM}"; DST="${3:?falta destino}"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
CHUNK_CHARS=350000   # tamano de fragmento en caracteres base64

cleanup(){ qm guest exec "$VMID" -- powershell.exe -Command \
  "Remove-Item -Force C:\Windows\Temp\_ex.b64 -ErrorAction SilentlyContinue" >/dev/null 2>&1 || true
  rm -f /tmp/_full.b64 /tmp/_ex.b64 2>/dev/null || true; }
trap cleanup EXIT

echo "Extrayendo $SRC de la VM $VMID (Windows, por agente QEMU)..."

# 1. Codificar a base64 EN LA VICTIMA con PowerShell y guardar en disco
qm guest exec "$VMID" -- powershell.exe -Command \
  "[Convert]::ToBase64String([IO.File]::ReadAllBytes('$SRC')) | Set-Content -Path C:\Windows\Temp\_ex.b64 -Encoding ascii" \
  >/dev/null 2>&1

# 2. Obtener el tamano del base64 para trocear la lectura
LEN=$(qm guest exec "$VMID" -- powershell.exe -Command \
  "(Get-Item C:\Windows\Temp\_ex.b64).Length" 2>/dev/null \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('out-data','0').strip())")

if [ -z "$LEN" ] || [ "$LEN" = "0" ]; then
  echo -e "${RED}[!] No se genero el base64 en la victima (ruta o permisos?)${NC}"; exit 1
fi

# 3. Leer el base64 por fragmentos (Substring en PowerShell) y concatenar en el host
> /tmp/_full.b64
OFFSET=0
echo -n "    leyendo ($LEN chars): "
while [ "$OFFSET" -lt "$LEN" ]; do
  CHUNK=$(qm guest exec "$VMID" -- powershell.exe -Command \
    "\$c=Get-Content -Raw C:\Windows\Temp\_ex.b64; \$len=[Math]::Min($CHUNK_CHARS, \$c.Length-$OFFSET); \$c.Substring($OFFSET,\$len)" 2>/dev/null \
    | python3 -c "import sys,json;print(json.load(sys.stdin).get('out-data',''),end='')")
  printf '%s' "$CHUNK" | tr -d '\r\n' >> /tmp/_full.b64
  OFFSET=$((OFFSET + CHUNK_CHARS))
  echo -n "."
done
echo ""

# 4. Decodificar en el host
if base64 -d /tmp/_full.b64 > "$DST" 2>/dev/null; then
  echo -e "${GREEN}[OK] $(stat -c%s "$DST") bytes en $DST${NC}"
  echo -e "    sha256: $(sha256sum "$DST" | cut -d' ' -f1)"
else
  echo -e "${RED}[!] Error al decodificar el base64${NC}"; exit 1
fi
