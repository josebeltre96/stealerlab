#!/bin/bash
# STEALERLAB - captura.sh (v5) - captura en el sinkhole (ens18), donde converge el trafico.
# El proceso tcpdump corre en primer plano DENTRO del sinkhole; el host mantiene
# la sesion SSH en background LOCAL (fiable) y guarda su PID para detenerla.
set -uo pipefail
ACTION="${1:?falta accion}"; CASO="${2:?falta caso}"
SINK_MGMT="10.10.99.2"; OUTDIR="/opt/lab/pcap/${CASO}"
SSHPID="/tmp/cap_ssh_${CASO}.pid"
GREEN='\033[0;32m'; NC='\033[0m'
case "$ACTION" in
  start)
    ssh -o StrictHostKeyChecking=no lab@$SINK_MGMT "sudo mkdir -p $OUTDIR" 2>/dev/null
    # SSH en background LOCAL del host, tcpdump en primer plano dentro del sinkhole
    ssh -o StrictHostKeyChecking=no lab@$SINK_MGMT \
      "sudo tcpdump -i ens18 -n -s0 -C 100 -W 10 -w ${OUTDIR}/captura.pcap 'net 10.10.66.0/24'" \
      >/dev/null 2>&1 &
    echo $! > "$SSHPID"
    sleep 2
    echo -e "${GREEN}    captura-activa en sinkhole ens18 (${CASO})${NC}"
    ;;
  stop)
    # Detener tcpdump en el sinkhole y cerrar la sesion SSH local
    ssh -o StrictHostKeyChecking=no lab@$SINK_MGMT "sudo pkill -f 'tcpdump.*${CASO}'" 2>/dev/null || true
    [ -f "$SSHPID" ] && kill "$(cat "$SSHPID")" 2>/dev/null; rm -f "$SSHPID"
    echo -e "${GREEN}    captura-detenida${NC}"
    ;;
esac
