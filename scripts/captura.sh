#!/bin/bash
# ============================================================
# STEALERLAB - captura.sh (v6)
# Captura directamente en el sinkhole, sobre ens18, donde converge
# el trafico del segmento 10.10.66.0/24.
# Uso: ./captura.sh {start|stop} <caso>
# ============================================================
set -euo pipefail
ACTION="${1:?falta accion}"; CASO="${2:?falta caso}"
SINK_MGMT="10.10.99.2"
OUTDIR="/opt/lab/pcap/${CASO}"
REMOTE_PID="/tmp/stealerlab_tcpdump_${CASO}.pid"
GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
SSH=(ssh -o BatchMode=yes -o StrictHostKeyChecking=no "lab@${SINK_MGMT}")

case "$ACTION" in
  start)
    "${SSH[@]}" "sudo mkdir -p '$OUTDIR'; sudo rm -f '$REMOTE_PID'; sudo nohup tcpdump -i ens18 -n -s0 -C 100 -W 10 -w '$OUTDIR/captura.pcap' 'net 10.10.66.0/24' >/dev/null 2>&1 & echo \$! | sudo tee '$REMOTE_PID' >/dev/null"
    sleep 2
    if "${SSH[@]}" "test -s '$REMOTE_PID' && sudo kill -0 \$(cat '$REMOTE_PID')" >/dev/null 2>&1; then
      echo -e "${GREEN}    captura-activa en sinkhole ens18 (${CASO})${NC}"
    else
      echo -e "${RED}    [FAIL] tcpdump no quedo activo${NC}"; exit 1
    fi
    ;;
  stop)
    "${SSH[@]}" "if test -s '$REMOTE_PID'; then sudo kill \$(cat '$REMOTE_PID') 2>/dev/null || true; rm -f '$REMOTE_PID'; fi" || true
    sleep 1
    echo -e "${GREEN}    captura-detenida (${CASO})${NC}"
    ;;
  *) echo "Uso: $0 {start|stop} <caso>"; exit 2 ;;
esac
