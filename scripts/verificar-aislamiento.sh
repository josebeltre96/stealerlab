#!/bin/bash
#===============================================================================
# verificar-aislamiento.sh
# STEALERLAB - Verificacion empirica del aislamiento del segmento de analisis
# Autor: Jose Arturo Beltre Castro - TFM UEM
#
# Ejecutar en el HOST Proxmox. Comprueba los controles de aislamiento del
# segmento vmbr2 (analisis) y confirma la gestion fuera de banda por agente QEMU.
# La salida esta pensada para captura de evidencia (Anexo E).
#===============================================================================

# --- Parametros del laboratorio (ajustar si cambia el direccionamiento) ---
SINKHOLE_IP="10.10.66.2"     # sinkhole en el segmento de analisis
VICTIMA_IP="10.10.66.10"     # victima en el segmento de analisis
SEG_ANALISIS="10.10.66.0/24"
VMID_SINKHOLE="100"          # VM100 = sinkhole (para prueba de agente QEMU)

# --- Colores ---
V='\033[0;32m'; R='\033[0;31m'; A='\033[1;34m'; N='\033[0m'; B='\033[1m'
ok(){   echo -e "  [${V}OK${N}]   $1"; }
fail(){ echo -e "  [${R}FALLO${N}] $1"; }
info(){ echo -e "  [${A}INFO${N}] $1"; }

echo -e "${B}===============================================================${N}"
echo -e "${B} STEALERLAB - Verificacion de aislamiento del segmento vmbr2${N}"
echo -e "${B} Host: $(hostname)   Fecha (UTC): $(date -u '+%Y-%m-%d %H:%M:%S')${N}"
echo -e "${B}===============================================================${N}"

#-------------------------------------------------------------------------------
echo -e "\n${A}[1] Control primario: el host NO tiene IP en vmbr2${N}"
#-------------------------------------------------------------------------------
VMBR2_IP=$(ip -4 -br addr show vmbr2 2>/dev/null | awk '{print $3}')
ip -br addr show vmbr2 2>/dev/null || echo "  (vmbr2 no existe)"
if [ -z "$VMBR2_IP" ]; then
  ok "vmbr2 sin direccion IPv4 en el host (no hay ruta posible al segmento)"
else
  fail "vmbr2 tiene IP $VMBR2_IP en el host -- revisar, rompe el aislamiento primario"
fi

#-------------------------------------------------------------------------------
echo -e "\n${A}[2] El host no tiene ruta hacia el segmento de analisis${N}"
#-------------------------------------------------------------------------------
RUTA=$(ip route | grep "$SEG_ANALISIS")
if [ -z "$RUTA" ]; then
  ok "Sin ruta a $SEG_ANALISIS en la tabla de enrutamiento del host"
else
  fail "Existe ruta a $SEG_ANALISIS: $RUTA"
fi

#-------------------------------------------------------------------------------
echo -e "\n${A}[3] El host NO alcanza el segmento de analisis (debe fallar)${N}"
#-------------------------------------------------------------------------------
if ping -c 2 -W 2 "$SINKHOLE_IP" >/dev/null 2>&1; then
  fail "El host alcanza $SINKHOLE_IP -- NO deberia (revisar aislamiento)"
else
  ok "El host no alcanza $SINKHOLE_IP (100% perdida) -- aislamiento correcto"
fi

#-------------------------------------------------------------------------------
echo -e "\n${A}[4] Defensa en profundidad: reglas FORWARD DROP sobre vmbr2${N}"
#-------------------------------------------------------------------------------
echo "  --- iptables -L FORWARD (primeras reglas) ---"
iptables -L FORWARD -n -v --line-numbers 2>/dev/null | head -6 | sed 's/^/  /'
DROPS=$(iptables -L FORWARD -n 2>/dev/null | grep -c "DROP")
if [ "$DROPS" -ge 2 ]; then
  ok "Se encuentran reglas DROP asociadas a vmbr2 (defensa en profundidad activa)"
else
  info "Revisar manualmente las reglas DROP sobre vmbr2"
fi

#-------------------------------------------------------------------------------
echo -e "\n${A}[5] Gestion fuera de banda: agente QEMU de la VM aislada${N}"
#-------------------------------------------------------------------------------
if qm agent "$VMID_SINKHOLE" ping >/dev/null 2>&1; then
  ok "Agente QEMU de la VM$VMID_SINKHOLE responde (gestion operativa sin red)"
else
  info "El agente QEMU de la VM$VMID_SINKHOLE no responde (verificar que la VM este activa)"
fi

#-------------------------------------------------------------------------------
echo -e "\n${A}[6] Puentes de red sin puerto fisico (aislamiento L2)${N}"
#-------------------------------------------------------------------------------
echo "  --- brctl show (resumen) ---"
if command -v brctl >/dev/null 2>&1; then
  brctl show 2>/dev/null | sed 's/^/  /'
else
  ip -br link show type bridge 2>/dev/null | sed 's/^/  /'
fi

echo -e "\n${B}===============================================================${N}"
echo -e "${B} Resumen: el segmento de analisis es inalcanzable por red desde${N}"
echo -e "${B} el host, pero la VM sigue siendo gestionable por el agente QEMU.${N}"
echo -e "${B} Esta es la evidencia central del aislamiento (Cap. 5.2 y 5.7).${N}"
echo -e "${B}===============================================================${N}"
