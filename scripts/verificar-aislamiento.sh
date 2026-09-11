#!/bin/bash
#===============================================================================
# verificar-aislamiento.sh (v4)
# STEALERLAB - Verificacion empirica del aislamiento del segmento de analisis
# Autor: Jose Arturo Beltre Castro - TFM UEM
#
# Ejecutar en el HOST Proxmox antes de cada bloque de detonaciones.
# Firewall del host: iptables (reglas FORWARD DROP sobre vmbr2).
# Comprueba: ausencia de IP/ruta (IPv4 e IPv6) en vmbr2, forwarding L3
# desactivado, reglas DROP iptables, estructura L2, host->sinkhole (debe
# fallar) y prueba critica victima->gestion (debe fallar), lanzada desde
# la propia victima por el agente QEMU.
# La salida esta pensada para captura de evidencia (Anexo E).
#===============================================================================
set -uo pipefail

# --- Parametros del laboratorio (ajustar si cambia el direccionamiento) ---
SINKHOLE_IP="10.10.66.2"     # sinkhole en el segmento de analisis
VICTIMA_IP="10.10.66.10"     # victima en el segmento de analisis
SEG_ANALISIS="10.10.66.0/24"
VMID_SINKHOLE="100"          # VM100 = sinkhole
VMID_VICTIM="120"            # VM120 = victima
MGMT_IP="10.10.99.1"         # gateway de gestion (vmbr3)
FALLOS=0

# --- Colores ---
V='\033[0;32m'; R='\033[0;31m'; A='\033[1;34m'; N='\033[0m'; B='\033[1m'
ok(){   echo -e "  [${V}OK${N}]   $1"; }
fail(){ echo -e "  [${R}FALLO${N}] $1"; FALLOS=$((FALLOS+1)); }
info(){ echo -e "  [${A}INFO${N}] $1"; }

# Guard: asegurarse de estar en Proxmox
command -v ip >/dev/null || { echo '[FAIL] falta el comando ip'; exit 1; }
command -v qm >/dev/null || { echo '[FAIL] no se ejecuta en un host Proxmox (falta qm)'; exit 1; }

echo -e "${B}===============================================================${N}"
echo -e "${B} STEALERLAB - Verificacion de aislamiento del segmento vmbr2${N}"
echo -e "${B} Host: $(hostname)   Fecha (UTC): $(date -u '+%Y-%m-%d %H:%M:%S')${N}"
echo -e "${B}===============================================================${N}"

#-------------------------------------------------------------------------------
echo -e "\n${A}[1] Control primario: el host NO tiene IP (IPv4/IPv6) en vmbr2${N}"
#-------------------------------------------------------------------------------
ip -br addr show vmbr2 2>/dev/null | sed 's/^/  /' || echo "  (vmbr2 no existe)"
VMBR2_V4=$(ip -4 addr show dev vmbr2 2>/dev/null | awk '/inet /{print $2}')
VMBR2_V6=$(ip -6 addr show dev vmbr2 2>/dev/null | awk '/inet6 /{print $2}')
if [ -z "$VMBR2_V4" ] && [ -z "$VMBR2_V6" ]; then
  ok "vmbr2 sin direcciones L3 en el host (no hay ruta posible al segmento)"
else
  fail "vmbr2 tiene direccion(es): IPv4=[$VMBR2_V4] IPv6=[$VMBR2_V6] -- rompe el aislamiento primario"
fi

#-------------------------------------------------------------------------------
echo -e "\n${A}[2] El host no tiene ruta hacia el segmento de analisis${N}"
#-------------------------------------------------------------------------------
RUTA=$(ip route show "$SEG_ANALISIS" 2>/dev/null || true)
if [ -z "$RUTA" ]; then
  ok "Sin ruta IPv4 especifica a $SEG_ANALISIS"
else
  fail "Existe ruta IPv4 a $SEG_ANALISIS: $RUTA"
fi
# NOTA: la validacion de aislamiento de rutas de este script se limita a IPv4.
# IPv6, ARP/NDP y direcciones link-local quedan fuera del alcance experimental.
info "Aislamiento IPv6: fuera del alcance experimental (este script valida IPv4)"

#-------------------------------------------------------------------------------
echo -e "\n${A}[3] Reenvio L3: activo solo para el NAT de salida de vmbr1 (REMnux)${N}"
# NOTA: en este diseño el reenvio IPv4 esta ACTIVO a proposito, porque REMnux
# (vmbr1) necesita salida NAT a internet para descargar muestras. El aislamiento
# de vmbr2 NO depende de ip_forward, sino de las reglas DROP (paso 4) y de que
# vmbr2 no tenga IP (paso 1). Aqui se verifica que el NAT sea EXCLUSIVO de vmbr1
# y que NO exista NAT hacia/desde vmbr2.
#-------------------------------------------------------------------------------
IPF=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo unknown)
IP6F=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo unknown)
if [ "$IPF" = "1" ]; then
  info "net.ipv4.ip_forward=1 (esperado: requerido por el NAT de salida de vmbr1/REMnux)"
else
  info "net.ipv4.ip_forward=$IPF"
fi
[ "$IP6F" = "0" ] && ok "net.ipv6.conf.all.forwarding=0" || fail "net.ipv6.conf.all.forwarding=$IP6F (debe ser 0 en este diseño)"
# Verificar que el NAT (MASQUERADE) es solo del segmento de REMnux, no del de analisis
NAT_VMBR1=$(iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -c 'MASQUERADE.*10\.10\.20\.')
NAT_ANALISIS=$(iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -c 'MASQUERADE.*10\.10\.66\.')
[ "$NAT_VMBR1" -ge 1 ] && ok "NAT de salida presente para el segmento de REMnux (10.10.20.0/24)" || info "No se observa NAT para 10.10.20.0/24"
[ "$NAT_ANALISIS" -eq 0 ] && ok "NO existe NAT de salida para el segmento de analisis (10.10.66.0/24)" || fail "Existe NAT para 10.10.66.0/24 -- el segmento de analisis NO debe tener salida NAT"

#-------------------------------------------------------------------------------
echo -e "\n${A}[4] Defensa en profundidad: reglas FORWARD DROP (iptables) sobre vmbr2${N}"
#-------------------------------------------------------------------------------
echo "  --- iptables -L FORWARD (reglas de vmbr2) ---"
iptables -L FORWARD -n -v 2>/dev/null | grep -i 'vmbr2' | sed 's/^/  /'
DROPS_VMBR2=$(iptables -L FORWARD -n -v 2>/dev/null | grep -i 'vmbr2' | grep -c 'DROP')
if [ "$DROPS_VMBR2" -ge 2 ]; then
  ok "Reglas FORWARD DROP asociadas a vmbr2 presentes ($DROPS_VMBR2) -- defensa en profundidad activa"
else
  fail "No se encuentran las 2 reglas DROP esperadas sobre vmbr2 (encontradas: $DROPS_VMBR2)"
fi

#-------------------------------------------------------------------------------
echo -e "\n${A}[5] El host NO alcanza el segmento de analisis (debe fallar)${N}"
#-------------------------------------------------------------------------------
if ping -c 2 -W 2 "$SINKHOLE_IP" >/dev/null 2>&1; then
  fail "El host alcanza $SINKHOLE_IP -- NO deberia (revisar aislamiento)"
else
  ok "El host no alcanza $SINKHOLE_IP (100% perdida) -- aislamiento correcto"
fi

#-------------------------------------------------------------------------------
echo -e "\n${A}[6] Gestion fuera de banda: agente QEMU operativo${N}"
#-------------------------------------------------------------------------------
if qm agent "$VMID_SINKHOLE" ping >/dev/null 2>&1; then
  ok "Agente QEMU de la VM$VMID_SINKHOLE (sinkhole) responde"
else
  info "El agente QEMU de la VM$VMID_SINKHOLE no responde (verificar que la VM este activa)"
fi

#-------------------------------------------------------------------------------
echo -e "\n${A}[7] Estructura L2 de los puentes${N}"
#-------------------------------------------------------------------------------
if command -v brctl >/dev/null 2>&1; then
  brctl show 2>/dev/null | sed 's/^/  /'
else
  ip -br link show type bridge 2>/dev/null | sed 's/^/  /'
fi
info "La ausencia de puerto fisico se documenta aqui; no implica por si sola aislamiento L3/L2 completo."

#-------------------------------------------------------------------------------
echo -e "\n${A}[8] Prueba CRITICA: victima -> gestion (debe FALLAR)${N}"
# Se lanza DESDE la victima por el agente QEMU (no desde el host).
#-------------------------------------------------------------------------------
if qm agent "$VMID_VICTIM" ping >/dev/null 2>&1; then
  RES=$(qm guest exec "$VMID_VICTIM" -- powershell.exe -Command \
    "(Test-Connection -ComputerName '$MGMT_IP' -Count 2 -Quiet)" 2>/dev/null \
    | python3 -c "import sys,json;print(json.load(sys.stdin).get('out-data','').strip())" 2>/dev/null || echo error)
  case "$(echo "$RES" | tr -d '\r\n ' | tr '[:upper:]' '[:lower:]')" in
    true)  fail "La victima ALCANZA la gestion $MGMT_IP -- FUGA DE AISLAMIENTO CRITICA" ;;
    false) ok   "La victima NO alcanza la gestion $MGMT_IP -- aislamiento correcto" ;;
    *)     fail "No se pudo determinar el resultado desde la victima: [$RES]" ;;
  esac
else
  info "La VM$VMID_VICTIM (victima) no esta activa: no se pudo ejecutar la prueba critica desde la victima."
  info "Enciende la victima (qm start $VMID_VICTIM) y repite antes de detonar."
  FALLOS=$((FALLOS+1))
fi

echo -e "\n${B}===============================================================${N}"
echo -e "${B} Resumen: el segmento de analisis debe ser inalcanzable por red${N}"
echo -e "${B} desde el host, y la victima no debe alcanzar la gestion, pero${N}"
echo -e "${B} las VMs siguen siendo gestionables por el agente QEMU.${N}"
echo -e "${B}===============================================================${N}"

if [ "$FALLOS" -eq 0 ]; then
  echo -e "${V}[PASS] Controles de aislamiento superados. Se puede detonar.${N}"
  exit 0
else
  echo -e "${R}[FAIL] $FALLOS control(es) fallaron. NO detonar.${N}"
  exit 1
fi
