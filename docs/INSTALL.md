# Guía de despliegue — STEALERLAB

Montaje del laboratorio desde cero. Valores de red del laboratorio de referencia; ajústalos a tu entorno.

> Este laboratorio ejecuta malware real. No lo despliegues en producción ni en hardware con datos sensibles.

## 0. Arquitectura y red
- vmbr1 10.10.20.0/24 (NAT/internet, solo REMnux) · vmbr2 10.10.66.0/24 (análisis, **host SIN IP**) · vmbr3 10.10.99.0/24 (gestión)
- VM100 sinkhole (ens18 .66.2, ens19 .99.2) · VM110 REMnux (ens18 .20.10, cap0 sin IP) · VM120 víctima (.66.10)

## 1. Host Proxmox
- Proxmox VE 9.x. Bridges según arriba; **vmbr2 sin IP** (`iface vmbr2 inet manual`).
- MASQUERADE de vmbr1 sobre la NIC física (ej. enp1s0f0).
- Servicio de aislamiento (FORWARD DROP sobre vmbr2):
```
iptables -I FORWARD -i vmbr2 -j DROP
iptables -I FORWARD -o vmbr2 -j DROP
```

## 2. VM100 Sinkhole
- Debian/Ubuntu. INetSim + mitmproxy + nftables (ver config-templates/).
- Usuario `lab` con SSH por clave (el host extrae mitmdump.log por vmbr3).
- **La captura de tráfico se hace aquí** (ens18), no en cap0 — el bridge no entrega unicast a cap0.

## 3. VM110 REMnux
- REMnux. ens18 en vmbr1 (internet), cap0 en vmbr2 sin IP.
- `ip_forward=0` (evitar fuga por multihoming).
- Zeek, 7-Zip. /opt/lab/reports/ y /opt/lab/muestras-cifradas/.

## 4. VM120 Víctima (Windows 10)
- Windows 10 Pro x64 build 19045.6456. Interfaz en vmbr2 (.66.10, gw/DNS .66.2).
- Agente QEMU (qemu-guest-agent) — imprescindible.
- Sysmon 15.21 (config SwiftOnSecurity). RealTimeIsUniversal=1 (UTC).
- Instalar CA de mitmproxy en el almacén de confianza.
- Defender OFF. Anti-anti-VM: ver config-templates/win10-antivm-args.template.
- Crear snapshot `golden-detonacion` con la VM apagada.

## 5. Scripts
```bash
git clone <repo> /root/stealerlab-final
chmod +x /root/stealerlab-final/scripts/*.sh
cp config-templates/env.template /opt/lab/.env   # rellenar MB_AUTH_KEY
```
Rutas en los scripts: STAGE_HOST=/root/stealerlab-final/stage, EXTRACTOR y CAPSCRIPT en scripts/.

## 6. Verificar y operar
```bash
./scripts/verificar-aislamiento.sh    # [PASS] obligatorio
./scripts/preparar.sh <sha256> <familia>
# detonar en VNC, observar 15 min
./scripts/recoger.sh
./scripts/triaje.sh
```

## Lecciones de la validación (detonación real LummaC2)
- Aislamiento verificado con test víctima→gestión (PASS).
- EVTX extraído correctamente por agente QEMU con PowerShell (un EVTX de 66 MB tarda por el troceado).
- C2 grzpoint.cyou capturado; evidencia de red vía mitmdump.log del sinkhole.
- Captura PCAP: en el sinkhole (ens18); requiere sudoers NOPASSWD para lanzamiento desatendido.
