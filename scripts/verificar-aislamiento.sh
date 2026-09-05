#!/bin/bash
#===============================================================================
# STEALERLAB - verificar-aislamiento.sh (v3)
# Ejecutar en el host Proxmox antes de cada bloque de detonaciones.
# Comprueba: ausencia de IP/ruta en vmbr2, forwarding L3 desactivado,
# evidencia de filtrado nftables IPv4/IPv6, estructura L2 y prueba efectiva
# desde la victima hacia gestion.
#===============================================================================
set -uo pipefail
VMBR2="vmbr2"; SEG_ANALISIS="10.10.66.0/24"; SINKHOLE_IP="10.10.66.2"
VMID_VICTIM="120"; MGMT_IP="10.10.99.1"
FALLOS=0
V='\033[0;32m'; R='\033[0;31m'; A='\033[1;34m'; N='\033[0m'; B='\033[1m'
ok(){ echo -e "  [${V}OK${N}]   $1"; }
fail(){ echo -e "  [${R}FALLO${N}] $1"; FALLOS=$((FALLOS+1)); }
info(){ echo -e "  [${A}INFO${N}] $1"; }

command -v ip >/dev/null || { echo '[FAIL] falta ip'; exit 1; }
command -v qm >/dev/null || { echo '[FAIL] no se ejecuta en Proxmox'; exit 1; }

echo -e "${B}===============================================================${N}"
echo -e "${B} STEALERLAB - Verificacion empirica de aislamiento${N}"
echo -e "${B} Host: $(hostname) | UTC: $(date -u '+%Y-%m-%d %H:%M:%S.%3N')${N}"
echo -e "${B}===============================================================${N}"

echo -e "\n${A}[1] vmbr2 sin direccion IPv4/IPv6 en el host${N}"
V4=$(ip -4 addr show dev "$VMBR2" 2>/dev/null | awk '/inet /{print $2}')
V6=$(ip -6 addr show dev "$VMBR2" 2>/dev/null | awk '/inet6 /{print $2}')
[ -z "$V4" ] && [ -z "$V6" ] && ok "$VMBR2 sin direcciones L3 en el host" || fail "$VMBR2 tiene direccion(es): IPv4=[$V4] IPv6=[$V6]"

echo -e "\n${A}[2] Sin ruta L3 directa al segmento de analisis${N}"
RUTA=$(ip route show "$SEG_ANALISIS" 2>/dev/null || true)
[ -z "$RUTA" ] && ok "Sin ruta IPv4 especifica a $SEG_ANALISIS" || fail "Existe ruta IPv4: $RUTA"
RUTA6=$(ip -6 route show 2>/dev/null | grep -F '10.10.66.' || true)
[ -z "$RUTA6" ] || fail "Existe ruta IPv6 relacionada con 10.10.66: $RUTA6"

echo -e "\n${A}[3] Forwarding L3 del host desactivado${N}"
IPF=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo unknown)
IP6F=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo unknown)
[ "$IPF" = "0" ] && ok "net.ipv4.ip_forward=0" || fail "net.ipv4.ip_forward=$IPF (debe ser 0 en este diseño)"
[ "$IP6F" = "0" ] && ok "net.ipv6.conf.all.forwarding=0" || fail "net.ipv6.conf.all.forwarding=$IP6F (debe ser 0 en este diseño)"

echo -e "\n${A}[4] nftables: defensa de forwarding y ausencia de NAT hacia vmbr2${N}"
if command -v nft >/dev/null 2>&1; then
  NFT=$(nft list ruleset 2>/dev/null || true)
  echo "$NFT" | grep -Fq 'vmbr2' && ok 'El ruleset nftables referencia vmbr2' || fail 'nftables no muestra referencia a vmbr2'
  echo "$NFT" | grep -Eiq '\b(drop|reject)\b' && ok 'El ruleset contiene drop/reject' || fail 'No se observa drop/reject en nftables'
  if echo "$NFT" | grep -Eiq 'vmbr2.*(snat|masquerade|dnat)|((snat|masquerade|dnat).*vmbr2)'; then
    fail 'Se observa NAT asociado a vmbr2; revisar inmediatamente'
  else
    ok 'No se observa NAT asociado textualmente a vmbr2'
  fi
else
  fail 'nft no disponible; no se puede verificar el firewall del diseño'
fi

echo -e "\n${A}[5] Estructura L2 de vmbr2${N}"
ip -br link show "$VMBR2" 2>/dev/null | sed 's/^/  /'
if command -v bridge >/dev/null 2>&1; then
  bridge link show 2>/dev/null | grep -F "$VMBR2" | sed 's/^/  /' || true
fi
info 'La ausencia de puerto fisico se documenta aqui; no implica por si sola aislamiento L3/L2 completo.'

echo -e "\n${A}[6] Prueba efectiva: host -> sinkhole (debe FALLAR)${N}"
if ping -c 2 -W 2 "$SINKHOLE_IP" >/dev/null 2>&1; then fail "El host alcanza $SINKHOLE_IP"; else ok "El host no alcanza $SINKHOLE_IP"; fi

echo -e "\n${A}[7] Prueba critica: victima -> gestion (debe FALLAR)${N}"
RES=$(qm guest exec "$VMID_VICTIM" -- powershell.exe -Command "(Test-Connection -ComputerName '$MGMT_IP' -Count 2 -Quiet)" 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin).get('out-data','').strip())" 2>/dev/null || echo error)
case "$(echo "$RES" | tr -d '\r\n ' | tr '[:upper:]' '[:lower:]')" in
  true) fail "La victima alcanza gestion $MGMT_IP -- FUGA CRITICA";;
  false) ok "La victima no alcanza gestion $MGMT_IP";;
  *) fail "No se pudo determinar resultado de la prueba desde la victima: [$RES]";;
esac

echo -e "\n${B}===============================================================${N}"
if [ "$FALLOS" -eq 0 ]; then
  echo -e "${V}[PASS] Controles de aislamiento superados. Se puede detonar.${N}"; exit 0
else
  echo -e "${R}[FAIL] $FALLOS control(es) fallaron. NO detonar.${N}"; exit 1
fi
