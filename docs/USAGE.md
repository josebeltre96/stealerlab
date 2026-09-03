# Manual de uso del pipeline — STEALERLAB

## Ciclo de una detonación

1. **Preparar** el entorno:
   ```bash
   ./scripts/preparar.sh <sha256> <familia>
   ```
   Extrae la muestra cifrada, revierte la víctima a golden, sincroniza relojes,
   inicia la captura y monta la muestra.

2. **Detonar** manualmente la muestra en la víctima (por consola de Proxmox o agente).

3. **Observar** durante la ventana definida (15 minutos en el TFM).

4. **Recolectar** la evidencia:
   ```bash
   ./scripts/recoger.sh <caso>
   ```
   Genera el resumen Sysmon, procesa la captura con Zeek, recoge los flujos del
   sinkhole, crea una instantánea forense y revierte la víctima.

5. **Consolidar** los indicadores de todos los casos:
   ```bash
   ./scripts/triaje.sh
   ```
   Produce los CSV de IoC en `reports/_triaje/`.

## Extracción de binarios

```bash
./scripts/extraer-binario.sh <vmid> <ruta_en_la_vm> <destino_local>
```

Extrae un binario de una VM aislada por el agente QEMU, sin red.

## Verificación de integridad

```bash
sha256sum -c docs/MANIFEST.sha256
```
