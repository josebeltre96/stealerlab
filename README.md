# STEALERLAB

**Laboratorio de análisis dinámico de malware tipo *stealer* para Windows.**

Este repositorio acompaña al Trabajo Fin de Máster *«STEALERLAB: laboratorio de análisis dinámico de malware tipo stealer en Windows»* (Máster Universitario en Seguridad de las TIC, Universidad Europea, curso 2025-2026). Proporciona los scripts de automatización, las plantillas de configuración y las reglas de detección necesarias para construir y operar un laboratorio de análisis dinámico aislado y reproducible.

> **Aviso de seguridad.** Este repositorio **no contiene malware ni muestras**. Contiene únicamente la infraestructura de análisis (scripts, plantillas de configuración y reglas de detección). El manejo de muestras reales de malware es responsabilidad exclusiva de quien reproduzca el laboratorio, que debe operarlo en un entorno aislado y bajo su propia responsabilidad legal y técnica.

---

## Arquitectura

El laboratorio se compone de tres máquinas virtuales sobre Proxmox VE:

| VM   | Rol                        | Segmento              |
|------|----------------------------|-----------------------|
| 100  | Sinkhole (INetSim + mitmproxy) | Análisis + Gestión |
| 110  | REMnux (análisis forense)  | Internet + captura pasiva |
| 120  | Víctima (Windows 10)       | Análisis (aislado)    |

La separación de planos garantiza que la máquina que ejecuta el malware (víctima) carezca de ruta hacia el plano de gestión, extrayéndose su evidencia exclusivamente por el agente QEMU (fuera de banda). El detalle completo de la arquitectura, el direccionamiento y los controles de aislamiento está en el capítulo 5 del TFM.

---

## Contenido del repositorio

```
stealerlab/
├── scripts/              # Automatización del pipeline
│   ├── preparar.sh       # Prepara el entorno para una detonación
│   ├── recoger.sh        # Recolecta la evidencia post-detonación
│   ├── triaje.sh         # Consolida los IoC en CSV estructurados
│   ├── extraer-binario.sh# Extrae binarios de la VM aislada (agente QEMU)
│   ├── captura.sh        # Gestiona la captura de tráfico
│   └── verificar-aislamiento.sh  # Comprueba los controles de aislamiento
├── config-templates/     # Plantillas de configuración (SIN secretos)
│   ├── nftables.conf.template
│   ├── inetsim.conf.template
│   ├── mitmproxy.md
│   └── env.template      # Plantilla de variables (rellenar con tus claves)
├── rules/                # Reglas de detección
│   ├── stealerlab.yar    # Reglas YARA
│   └── sigma/            # Reglas Sigma (7 .yml)
├── docs/
│   ├── INSTALL.md        # Guía de despliegue paso a paso
│   ├── USAGE.md          # Manual de uso del pipeline
│   └── MANIFEST.sha256   # Hashes de integridad de los scripts
└── README.md
```

---

## Requisitos

- Proxmox VE 9.x
- Una VM Windows 10 con Sysmon (config SwiftOnSecurity) y el agente QEMU
- Una VM REMnux
- Una VM sinkhole con INetSim, mitmproxy y nftables

---

## Uso rápido

```bash
# 1. Verificar el aislamiento antes de operar
./scripts/verificar-aislamiento.sh

# 2. Preparar una detonación
./scripts/preparar.sh <sha256> <familia>

# 3. (detonar manualmente la muestra en la víctima)

# 4. Recolectar la evidencia
./scripts/recoger.sh <caso>

# 5. Consolidar los indicadores
./scripts/triaje.sh
```

Consulta `docs/INSTALL.md` y `docs/USAGE.md` para el detalle completo.

---

## Licencia y uso

Material académico para fines de investigación defensiva y educativos. Consulta con el autor antes de cualquier uso derivado.

## Autor

José Arturo Beltré Castro — TFM, Universidad Europea, 2025-2026.
Tutor: Carlos Pintos.
