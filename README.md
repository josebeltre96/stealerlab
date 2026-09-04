# STEALERLAB

**Laboratorio de análisis dinámico de malware tipo *stealer* para Windows.**

Repositorio del Trabajo Fin de Máster *«STEALERLAB»* (Máster Universitario en Seguridad de las TIC, Universidad Europea, 2025-2026). Autor: José Arturo Beltré Castro. Tutor: Carlos Pintos.

> **Los scripts han sido validados en una detonación real** (LummaC2): verificación de aislamiento (PASS), extracción de evidencia por agente QEMU, y captura de C2. Ver `docs/`.

> **Aviso:** este repositorio **no contiene malware ni muestras**, solo la infraestructura de análisis (scripts, plantillas de configuración y reglas de detección). Opéralo en un entorno aislado y bajo tu responsabilidad.

## Arquitectura

| VM  | Rol | Interfaces |
|-----|-----|-----------|
| 100 | Sinkhole (INetSim + mitmproxy) | ens18→vmbr2 (10.10.66.2) · ens19→vmbr3 (10.10.99.2) |
| 110 | REMnux (análisis forense) | ens18→vmbr1 (10.10.20.10) · cap0→vmbr2 (sin IP) |
| 120 | Víctima (Windows 10) | ens18→vmbr2 (10.10.66.10) |

La víctima (ejecuta malware) solo tiene interfaz en vmbr2 y su evidencia se extrae por el agente QEMU (fuera de banda). Segmento de análisis vmbr2 **sin IP en el host** = aislamiento primario.

## Contenido

```
scripts/       preparar · recoger · triaje · extraer-binario · verificar-aislamiento · montar-muestra · captura
config-templates/  nftables · mitmproxy · env · anti-anti-VM (plantillas SIN secretos)
rules/         stealerlab.yar (9 reglas, 3 niveles) · sigma/ (7 reglas)
docs/          INSTALL.md · USAGE.md · MANIFEST.sha256
```

## Uso rápido (host Proxmox)

```bash
./scripts/verificar-aislamiento.sh              # debe dar [PASS]
./scripts/preparar.sh <sha256> <familia>        # prepara y monta la muestra
# ... detonar manualmente en la victima, observar 15 min ...
./scripts/recoger.sh                            # recoge evidencia
./scripts/triaje.sh                             # consolida IoC
```

Detalle completo en `docs/INSTALL.md` y `docs/USAGE.md`.

## Verificación de integridad
```bash
sha256sum -c docs/MANIFEST.sha256
```
