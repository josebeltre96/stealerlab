# Guía de despliegue — STEALERLAB

Esta guía describe el despliegue del laboratorio desde cero. Requiere conocimientos de virtualización y administración de redes.

## 1. Host Proxmox

- Instalar Proxmox VE 9.x sobre el servidor físico.
- Configurar los puentes de red (bridges):
  - `vmbr1` → 10.10.20.1/24 (NAT, salida a internet controlada)
  - `vmbr2` → segmento de análisis, **SIN IP en el host** (control de aislamiento primario)
  - `vmbr3` → 10.10.99.1/24 (gestión)
- Aplicar la política de descarte de reenvío para `vmbr2` (ver `config-templates/nftables.conf.template`).

## 2. VM100 — Sinkhole

- Base Debian/Ubuntu.
- Dos interfaces: `ens18` en vmbr2 (10.10.66.2) y `ens19` en vmbr3 (10.10.99.2).
- Instalar INetSim, mitmproxy y nftables.
- Aplicar las plantillas de `config-templates/` (rellenando tus valores).
- El sinkhole actúa como gateway y DNS de la víctima, e intercepta el tráfico TLS.

## 3. VM110 — REMnux

- Desplegar REMnux (https://remnux.org).
- `ens18` en vmbr1 (10.10.20.10) para actualizaciones y consulta de repositorios.
- `cap0` en vmbr2 en modo pasivo (captura), sin IP.
- Nota: para capturar tráfico de la víctima en el bridge, configurar port mirroring o un tap, ya que un bridge Linux no reenvía por defecto el tráfico unicast entre puertos a una interfaz de escucha.

## 4. VM120 — Víctima

- Windows 10 Pro x64 (documentar build exacto).
- Instalar Sysmon con la configuración de SwiftOnSecurity.
- Instalar el agente QEMU (qemu-guest-agent).
- Interfaz única en vmbr2 (10.10.66.10), gateway y DNS = 10.10.66.2.
- Activar la clave de registro RealTimeIsUniversal para operar en UTC.
- Crear una instantánea limpia («golden») tras la preparación.

## 5. Verificación

Antes de operar, ejecutar en el host:

```bash
./scripts/verificar-aislamiento.sh
```

Todos los controles deben pasar (host sin IP ni ruta a vmbr2, ping al segmento falla, agente QEMU responde).
