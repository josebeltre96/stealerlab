#!/bin/bash
# ============================================================
# STEALERLAB - triaje.sh
# Consolida IoCs de todos los reportes de detonacion en tablas
# estructuradas para el TFM (Cap.6 + Anexos).
# Se ejecuta en REMnux (donde estan los reportes).
# Uso:  ./triaje.sh
# Salida: /opt/lab/reports/_triaje/  (CSVs + resumen)
# ============================================================
set -euo pipefail
REPORTS="/opt/lab/reports"
OUT="${REPORTS}/_triaje"
mkdir -p "$OUT"
GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'

# Ruido de Windows a excluir de los C2
NOISE='microsoft|windows|msft|google|live\.com|bing|edge|digicert|verisign|mozilla|azureedge|azure|msedge|windowsupdate|msftconnecttest|in-addr|ip6\.arpa|wpad|WORKGROUP|VLMCS|localmachine|DESKTOP-|clients2|gvt1|gstatic'

echo -e "${CYAN}=== TRIAJE STEALERLAB - Consolidacion de IoCs ===${NC}"
echo "Salida: $OUT"
echo ""

# ------------------------------------------------------------
# 1. Tabla de muestras (una fila por familia)
# ------------------------------------------------------------
echo -e "${CYAN}[1/6] Inventario de muestras...${NC}"
CSV_MUESTRAS="${OUT}/01_muestras.csv"
echo "familia,caso,sha256,fecha_deteccion_utc" > "$CSV_MUESTRAS"
if [ -f "${REPORTS}/casos.log" ]; then
  while IFS='|' read -r caso sha fam ts; do
    [ -z "$caso" ] && continue
    fam_short=$(echo "$caso" | cut -d_ -f1)
    echo "${fam},${caso},${sha},${ts}" >> "$CSV_MUESTRAS"
  done < "${REPORTS}/casos.log"
fi
echo -e "    ${GREEN}$(( $(wc -l < "$CSV_MUESTRAS") - 1 )) casos${NC}"

# ------------------------------------------------------------
# 2. C2 / dominios (excluyendo ruido de Windows)
# ------------------------------------------------------------
echo -e "${CYAN}[2/6] Extrayendo C2 y dominios...${NC}"
CSV_C2="${OUT}/02_c2_dominios.csv"
echo "familia,caso,dominio_c2,metodo,fuente" > "$CSV_C2"
for dir in "${REPORTS}"/*/; do
  caso=$(basename "$dir")
  [ "$caso" == "_triaje" ] && continue
  fam=$(echo "$caso" | cut -d_ -f1)
  # De c2_candidatas.txt (mitmproxy)
  if [ -f "${dir}c2_candidatas.txt" ]; then
    grep -oE '(GET|POST|CONNECT|HEAD) https?://[^/: ]+' "${dir}c2_candidatas.txt" 2>/dev/null \
      | sed -E 's#(GET|POST|CONNECT|HEAD) https?://##' \
      | grep -viE "$NOISE" | sort -u \
      | while read -r dom; do
          [ -n "$dom" ] && echo "${fam},${caso},${dom},HTTP/S,mitmproxy" >> "$CSV_C2"
        done
  fi
  # De sysmon_resumen.txt (DNS queries Id22)
  if [ -f "${dir}sysmon_resumen.txt" ]; then
    grep 'Id22' "${dir}sysmon_resumen.txt" 2>/dev/null \
      | grep -oE 'QueryName: [^ |]+' | sed 's/QueryName: //' \
      | grep -viE "$NOISE" | sort -u \
      | while read -r dom; do
          [ -n "$dom" ] && echo "${fam},${caso},${dom},DNS,sysmon" >> "$CSV_C2"
        done
  fi
done
sort -u -o "$CSV_C2" "$CSV_C2"
# reponer cabecera tras sort
grep -v '^familia,' "$CSV_C2" > "${CSV_C2}.tmp"
echo "familia,caso,dominio_c2,metodo,fuente" > "$CSV_C2"
cat "${CSV_C2}.tmp" >> "$CSV_C2"; rm -f "${CSV_C2}.tmp"
echo -e "    ${GREEN}$(( $(wc -l < "$CSV_C2") - 1 )) indicadores de red${NC}"

# ------------------------------------------------------------
# 3. Artefactos de host (ficheros creados por la muestra)
# ------------------------------------------------------------
echo -e "${CYAN}[3/6] Extrayendo artefactos de host...${NC}"
CSV_HOST="${OUT}/03_artefactos_host.csv"
echo "familia,caso,artefacto,tipo" > "$CSV_HOST"
for dir in "${REPORTS}"/*/; do
  caso=$(basename "$dir")
  [ "$caso" == "_triaje" ] && continue
  fam=$(echo "$caso" | cut -d_ -f1)
  if [ -f "${dir}sysmon_resumen.txt" ]; then
    # Ficheros en ProgramData, Temp, AppData, Prefetch creados (Id11)
    grep -F '[Id11] ' "${dir}sysmon_resumen.txt" 2>/dev/null \
      | grep -oE 'TargetFilename: [^|]+' | sed 's/TargetFilename: //' \
      | grep -iE 'ProgramData|\\Temp\\|AppData|Prefetch|muestra|\.lnk' \
      | grep -viE 'Edge|Chrome\\User|WER\\Report|SystemTemp\\__PS|LOG|\.tmp$' \
      | sort -u | head -30 \
      | while read -r art; do
          art_clean=$(echo "$art" | tr -d '\r' | sed 's/,/;/g')
          tipo="fichero"
          echo "$art" | grep -qi 'Prefetch' && tipo="prefetch"
          echo "$art" | grep -qi '.lnk' && tipo="acceso_directo"
          echo "$art" | grep -qi 'ProgramData' && tipo="artefacto_programdata"
          [ -n "$art_clean" ] && echo "${fam},${caso},${art_clean},${tipo}" >> "$CSV_HOST"
        done
  fi
done
echo -e "    ${GREEN}$(( $(wc -l < "$CSV_HOST") - 1 )) artefactos${NC}"

# ------------------------------------------------------------
# 4. Procesos ejecutados por la muestra
# ------------------------------------------------------------
echo -e "${CYAN}[4/6] Extrayendo procesos...${NC}"
CSV_PROC="${OUT}/04_procesos.csv"
echo "familia,caso,imagen,detalle" > "$CSV_PROC"
for dir in "${REPORTS}"/*/; do
  caso=$(basename "$dir")
  [ "$caso" == "_triaje" ] && continue
  fam=$(echo "$caso" | cut -d_ -f1)
  if [ -f "${dir}sysmon_resumen.txt" ]; then
    # CORRECCION (bug Id1/Id11): patron exacto '[Id1] ' para no capturar Id11, Id12, etc.
    grep -F '[Id1] ' "${dir}sysmon_resumen.txt" 2>/dev/null \
      | grep -iE 'muestra|ProgramData|\\Temp\\' \
      | grep -oE 'Image: [^|]+' | sed 's/Image: //' | tr -d '\r' \
      | sort -u \
      | while read -r img; do
          [ -n "$img" ] && echo "${fam},${caso},${img},proceso" >> "$CSV_PROC"
        done
  fi
done
echo -e "    ${GREEN}$(( $(wc -l < "$CSV_PROC") - 1 )) procesos${NC}"

# ------------------------------------------------------------
# 5. Estadisticas de telemetria por caso
# ------------------------------------------------------------
echo -e "${CYAN}[5/6] Estadisticas de telemetria...${NC}"
CSV_STATS="${OUT}/05_estadisticas.csv"
echo "familia,caso,eventos_sysmon,peticiones_c2,tam_mitmdump_bytes,logs_zeek" > "$CSV_STATS"
for dir in "${REPORTS}"/*/; do
  caso=$(basename "$dir")
  [ "$caso" == "_triaje" ] && continue
  fam=$(echo "$caso" | cut -d_ -f1)
  ev=$(wc -l < "${dir}sysmon_resumen.txt" 2>/dev/null || echo 0)
  c2=$(wc -l < "${dir}c2_candidatas.txt" 2>/dev/null || echo 0)
  mit=$(stat -c%s "${dir}mitmdump.log" 2>/dev/null || echo 0)
  pcapdir="/opt/lab/pcap/${caso}"
  zk=$(ls "${pcapdir}"/*.log 2>/dev/null | wc -l)
  echo "${fam},${caso},${ev},${c2},${mit},${zk}" >> "$CSV_STATS"
done
echo -e "    ${GREEN}estadisticas generadas${NC}"

# ------------------------------------------------------------
# 6. Resumen ejecutivo en texto
# ------------------------------------------------------------
echo -e "${CYAN}[6/6] Generando resumen ejecutivo...${NC}"
RESUMEN="${OUT}/00_RESUMEN.txt"
{
  echo "======================================================"
  echo "  STEALERLAB - RESUMEN DE TRIAJE"
  echo "  Generado: $(date -u '+%Y-%m-%d %H:%M:%S') UTC"
  echo "======================================================"
  echo ""
  echo "--- MUESTRAS ANALIZADAS ---"
  column -t -s, "$CSV_MUESTRAS" 2>/dev/null || cat "$CSV_MUESTRAS"
  echo ""
  echo "--- C2 / DOMINIOS DETECTADOS (sin ruido Windows) ---"
  column -t -s, "$CSV_C2" 2>/dev/null || cat "$CSV_C2"
  echo ""
  echo "--- ESTADISTICAS POR CASO ---"
  column -t -s, "$CSV_STATS" 2>/dev/null || cat "$CSV_STATS"
  echo ""
  echo "--- ARTEFACTOS DE HOST (muestra) ---"
  column -t -s, "$CSV_HOST" 2>/dev/null | head -40 || head -40 "$CSV_HOST"
  echo ""
  echo "======================================================"
  echo "Ficheros CSV en: $OUT"
  echo "  00_RESUMEN.txt        - este resumen"
  echo "  01_muestras.csv       - inventario"
  echo "  02_c2_dominios.csv    - C2 y dominios"
  echo "  03_artefactos_host.csv- ficheros/artefactos"
  echo "  04_procesos.csv       - procesos ejecutados"
  echo "  05_estadisticas.csv   - telemetria por caso"
} > "$RESUMEN"

echo ""
echo -e "${GREEN}=== TRIAJE COMPLETO ===${NC}"
echo -e "${YELLOW}Ver resumen:  cat ${RESUMEN}${NC}"
echo -e "${YELLOW}CSVs en:      ${OUT}/${NC}"
echo ""
cat "$RESUMEN"
