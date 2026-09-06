#!/bin/bash
# ============================================================
# STEALERLAB - captura.sh (v9)
# Captura directamente en el sinkhole, sobre ens18, donde converge
# el trafico del segmento 10.10.66.0/24.
# v9: correccion definitiva de dos problemas detectados:
#   - tcpdump baja privilegios al usuario 'tcpdump' y no podia crear
#     ficheros rotados (pcap0) en el directorio root -> se elimina la
#     rotacion -C/-W y se fija propietario del directorio a tcpdump.
#   - el & debe ir FUERA del setsid, con disown, para que sobreviva al SSH.
# Uso: ./captura.sh {start|stop} <caso>
# ============================================================
set -euo pipefail
ACTION="${1:?falta accion}"; CASO="${2:?falta caso}"
SINK_MGMT="10.10.99.2"
OUTDIR="/opt/lab/pcap/${CASO}"
GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
SSH=(ssh -o BatchMode=yes -o StrictHostKeyChecking=no "lab@${SINK_MGMT}")
case "$ACTION" in
  start)
    # 1. Crear el directorio y darle propiedad al usuario tcpdump (que es quien escribe)
    "${SSH[@]}" "sudo mkdir -p '$OUTDIR' && sudo chown tcpdump:tcpdump '$OUTDIR'"
    if ! "${SSH[@]}" "test -d '$OUTDIR'" >/dev/null 2>&1; then
      echo -e "${RED}    [FAIL] no se pudo crear el directorio $OUTDIR${NC}"; exit 1
    fi
    # 2. Lanzar tcpdump: setsid + & fuera + disown (metodo que sobrevive al SSH).
    #    Sin rotacion -C/-W (evita el problema de permisos al crear pcapN tras bajar privilegios).
    "${SSH[@]}" "sudo setsid tcpdump -i ens18 -n -s0 -w '$OUTDIR/captura.pcap' 'net 10.10.66.0/24' >'/tmp/tcpdump_${CASO}.err' 2>&1 </dev/null & disown"
    sleep 3
    # 3. Verificar que tcpdump quedo vivo
    if "${SSH[@]}" "sudo pgrep -f '$OUTDIR/captura.pcap' >/dev/null" >/dev/null 2>&1; then
      echo -e "${GREEN}    captura-activa en sinkhole ens18 (${CASO})${NC}"
    else
      echo -e "${RED}    [FAIL] tcpdump no quedo activo. Error:${NC}"
      "${SSH[@]}" "cat '/tmp/tcpdump_${CASO}.err' 2>/dev/null | head -3" || true
      exit 1
    fi
    ;;
  stop)
    "${SSH[@]}" "sudo pkill -f '$OUTDIR/captura.pcap' 2>/dev/null || true"
    sleep 1
    echo -e "${GREEN}    captura-detenida (${CASO})${NC}"
    ;;
  *) echo "Uso: $0 {start|stop} <caso>"; exit 2 ;;
esac
