#!/bin/bash
# ============================================================
# STEALERLAB - extraer-binario.sh (v2)
# Extrae un binario de una VM aislada troceando el base64 para no
# exceder el buffer del guest agent. Sin corrupcion.
# Uso: ./extraer-binario.sh <vmid> <ruta_en_vm> <destino_host>
# ============================================================
set -u
VMID="$1"; SRC="$2"; DST="$3"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

echo "Extrayendo $SRC de VM $VMID (por fragmentos)..."

# 1. Codificar a base64 en la VM y trocear en fragmentos de 200KB
qm guest exec $VMID -- bash -c "base64 -w0 '$SRC' > /tmp/_ex.b64 && split -b 200000 /tmp/_ex.b64 /tmp/_ex_part_ && ls /tmp/_ex_part_* | wc -l" >/dev/null 2>&1

# Obtener lista de fragmentos
PARTS=$(qm guest exec $VMID -- bash -c "ls /tmp/_ex_part_*" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('out-data',''))" 2>/dev/null)

if [ -z "$PARTS" ]; then echo -e "${RED}[!] No se generaron fragmentos${NC}"; exit 1; fi

NPARTS=$(echo "$PARTS" | wc -l)
echo "    $NPARTS fragmentos"

# 2. Leer cada fragmento y concatenar el base64
> /tmp/_full.b64
echo -n "    leyendo: "
for part in $PARTS; do
  CHUNK=$(qm guest exec $VMID -- cat "$part" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('out-data',''),end='')" 2>/dev/null)
  echo -n "$CHUNK" >> /tmp/_full.b64
  echo -n "."
done
echo ""

# 3. Decodificar
if base64 -d /tmp/_full.b64 > "$DST" 2>/dev/null; then
  echo -e "${GREEN}[OK] $(stat -c%s "$DST") bytes en $DST${NC}"
else
  echo -e "${RED}[!] Error al decodificar${NC}"; exit 1
fi

# 4. Limpiar
qm guest exec $VMID -- bash -c "rm -f /tmp/_ex.b64 /tmp/_ex_part_*" >/dev/null 2>&1
rm -f /tmp/_full.b64
