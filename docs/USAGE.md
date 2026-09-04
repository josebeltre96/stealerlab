# Manual de uso — STEALERLAB

## Ciclo de detonación
1. `./scripts/verificar-aislamiento.sh` — confirma aislamiento (debe dar [PASS])
2. `./scripts/preparar.sh <sha256> <familia>` — extrae muestra, revierte a golden, sincroniza relojes, monta la muestra
3. Detonar manualmente en la consola VNC de la víctima; observar 15 min
4. `./scripts/recoger.sh` — resumen Sysmon, EVTX, mitmdump, Zeek, snapshot forense, revierte
5. `./scripts/triaje.sh` — consolida IoC en /opt/lab/reports/_triaje/

## Notas operativas (lecciones de la validación)
- **Captura de red:** se realiza en el sinkhole (ens18), donde converge el tráfico de la víctima. El bridge Linux no entrega el tráfico unicast a cap0 (verificado: cap0 = 0 paquetes; sinkhole ens18 = tráfico completo). La evidencia de red principal es el mitmdump.log del sinkhole (TLS descifrado); el PCAP es complementario.
- **Extracción del EVTX:** por agente QEMU (base64 troceado en PowerShell). Un EVTX grande (p. ej. 66 MB) tarda varios minutos por el troceado; es el precio del aislamiento (extracción sin red). Para acelerar, exportar solo la ventana de la detonación con wevtutil /q.
- **Recuento de eventos:** se reporta el .Count real del motor (no el número de líneas de texto).
