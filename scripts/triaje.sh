#!/bin/bash
# ============================================================
# STEALERLAB - triaje.sh (v2)
# Consolida evidencia ya recolectada. No convierte heuristicas en C2
# confirmado ni atribuye automaticamente un artefacto al malware.
# Uso: ./triaje.sh
# ============================================================
set -euo pipefail
REPORTS="/opt/lab/reports"; OUT="${REPORTS}/_triaje"
mkdir -p "$OUT"
GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
NOISE='microsoft|windows|msft|google|live\.com|bing|edge|digicert|verisign|mozilla|azureedge|azure|msedge|windowsupdate|msftconnecttest|in-addr|ip6\.arpa|wpad|WORKGROUP|VLMCS|localmachine|DESKTOP-|clients2|gvt1|gstatic'

csv_count(){ awk -F, 'NR>1{n++} END{print n+0}' "$1" 2>/dev/null || echo 0; }

printf '%b\n' "${CYAN}=== TRIAJE STEALERLAB - Consolidacion de evidencia ===${NC}"
echo "Salida: $OUT"

# 1. Inventario
printf '%b\n' "${CYAN}[1/6] Inventario de muestras...${NC}"
CSV_MUESTRAS="$OUT/01_muestras.csv"; echo 'familia,caso,sha256,fecha_deteccion_utc' > "$CSV_MUESTRAS"
if [ -f "$REPORTS/casos.log" ]; then
  while IFS='|' read -r caso sha fam ts; do
    [ -n "$caso" ] || continue
    printf '%s,%s,%s,%s\n' "$fam" "$caso" "$sha" "$ts" >> "$CSV_MUESTRAS"
  done < "$REPORTS/casos.log"
fi
echo "    casos: $(csv_count "$CSV_MUESTRAS")"

# 2. Red: candidatos, no C2 confirmado
printf '%b\n' "${CYAN}[2/6] Indicadores de red candidatos...${NC}"
CSV_C2="$OUT/02_c2_candidatos.csv"; echo 'familia,caso,indicador,metodo,fuente,confianza,nota' > "$CSV_C2"
for dir in "$REPORTS"/*/; do
  [ -d "$dir" ] || continue; caso=$(basename "$dir"); [ "$caso" = "_triaje" ] && continue; fam="${caso%%_*}"
  if [ -f "$dir/c2_candidatas.txt" ]; then
    grep -oE '(GET|POST|CONNECT|HEAD) https?://[^/: ]+' "$dir/c2_candidatas.txt" 2>/dev/null \
      | sed -E 's#(GET|POST|CONNECT|HEAD) https?://##' | grep -viE "$NOISE" | sort -u \
      | while read -r dom; do [ -n "$dom" ] && printf '%s,%s,%s,%s,%s,%s,%s\n' "$fam" "$caso" "$dom" 'HTTP/S' 'mitmdump' 'candidata' 'Requiere correlacion temporal/proceso/destino y comparacion con control limpio' >> "$CSV_C2"; done
  fi
  if [ -f "$dir/sysmon_resumen.txt" ]; then
    grep -F '[Id22] ' "$dir/sysmon_resumen.txt" 2>/dev/null \
      | grep -oE 'QueryName: [^ |]+' | sed 's/QueryName: //' | grep -viE "$NOISE" | sort -u \
      | while read -r dom; do [ -n "$dom" ] && printf '%s,%s,%s,%s,%s,%s,%s\n' "$fam" "$caso" "$dom" 'DNS' 'Sysmon' 'candidata' 'DNS por si sola no demuestra C2' >> "$CSV_C2"; done
  fi
done
{ head -1 "$CSV_C2"; tail -n +2 "$CSV_C2" | sort -u; } > "$CSV_C2.tmp"; mv "$CSV_C2.tmp" "$CSV_C2"
echo "    indicadores unicos candidatos: $(csv_count "$CSV_C2")"

# 3. Artefactos: observados en Event ID 11, sin atribucion automatica
printf '%b\n' "${CYAN}[3/6] Artefactos observados (Sysmon Id11)...${NC}"
CSV_HOST="$OUT/03_artefactos_host.csv"; echo 'familia,caso,artefacto,tipo,confianza,nota' > "$CSV_HOST"
for dir in "$REPORTS"/*/; do
  [ -d "$dir" ] || continue; caso=$(basename "$dir"); [ "$caso" = "_triaje" ] && continue; fam="${caso%%_*}"
  [ -f "$dir/sysmon_resumen.txt" ] || continue
  grep -F '[Id11] ' "$dir/sysmon_resumen.txt" 2>/dev/null \
    | grep -oE 'TargetFilename: [^|]+' | sed 's/TargetFilename: //' \
    | grep -iE 'ProgramData|\\Temp\\|AppData|Prefetch|muestra|\.lnk' | sort -u | head -50 \
    | while read -r art; do
        [ -n "$art" ] || continue; clean=$(echo "$art" | tr -d '\r' | sed 's/,/;/g'); tipo='fichero'
        echo "$art" | grep -qi 'Prefetch' && tipo='prefetch'
        echo "$art" | grep -qi '\.lnk' && tipo='acceso_directo'
        echo "$art" | grep -qi 'ProgramData' && tipo='artefacto_programdata'
        printf '%s,%s,%s,%s,%s,%s\n' "$fam" "$caso" "$clean" "$tipo" 'observada' 'Event ID 11 no demuestra por si solo que el malware creo el fichero; correlacionar ProcessGuid/imagen/control' >> "$CSV_HOST"
      done
done
echo "    artefactos observados: $(csv_count "$CSV_HOST")"

# 4. Procesos: candidatos asociados a rutas de muestra
printf '%b\n' "${CYAN}[4/6] Procesos candidatos...${NC}"
CSV_PROC="$OUT/04_procesos.csv"; echo 'familia,caso,imagen,detalle,confianza,nota' > "$CSV_PROC"
for dir in "$REPORTS"/*/; do
  [ -d "$dir" ] || continue; caso=$(basename "$dir"); [ "$caso" = "_triaje" ] && continue; fam="${caso%%_*}"
  [ -f "$dir/sysmon_resumen.txt" ] || continue
  grep -F '[Id1] ' "$dir/sysmon_resumen.txt" 2>/dev/null \
    | grep -iE 'muestra|ProgramData|\\Temp\\' | grep -oE 'Image: [^|]+' | sed 's/Image: //' | tr -d '\r' | sort -u \
    | while read -r img; do [ -n "$img" ] && printf '%s,%s,%s,%s,%s,%s\n' "$fam" "$caso" "$img" 'Sysmon Id1' 'candidata' 'Correlacionar ProcessGuid, parent process y ventana de ejecucion' >> "$CSV_PROC"; done
done
echo "    procesos candidatos: $(csv_count "$CSV_PROC")"

# 5. Estadisticas con semantica explicita
printf '%b\n' "${CYAN}[5/6] Estadisticas de telemetria...${NC}"
CSV_STATS="$OUT/05_estadisticas.csv"; echo 'familia,caso,eventos_sysmon_1_3_11_22,peticiones_http_candidatas_lineas,dominios_candidatos_unicos,tam_mitmdump_bytes,logs_zeek' > "$CSV_STATS"
for dir in "$REPORTS"/*/; do
  [ -d "$dir" ] || continue; caso=$(basename "$dir"); [ "$caso" = "_triaje" ] && continue; fam="${caso%%_*}"
  ev=0
  if [ -f "$dir/sysmon_counts.csv" ]; then ev=$(awk -F, '{s+=$2} END{print s+0}' "$dir/sysmon_counts.csv"); else ev=$(grep -Ec '^.*\[(Id1|Id3|Id11|Id22)\] ' "$dir/sysmon_resumen.txt" 2>/dev/null || echo 0); fi
  c2=$(grep -Ec '^(GET|POST|CONNECT|HEAD) https?://' "$dir/c2_candidatas.txt" 2>/dev/null || echo 0)
  dom=$(grep -oE '(GET|POST|CONNECT|HEAD) https?://[^/: ]+' "$dir/c2_candidatas.txt" 2>/dev/null | sed -E 's#(GET|POST|CONNECT|HEAD) https?://##' | grep -viE "$NOISE" | sort -u | wc -l)
  mit=$(stat -c%s "$dir/mitmdump.log" 2>/dev/null || echo 0)
  pcapdir="$REPORTS/../pcap/$caso"; zk=$(find "$pcapdir" -maxdepth 1 -type f -name '*.log' 2>/dev/null | wc -l)
  printf '%s,%s,%s,%s,%s,%s,%s\n' "$fam" "$caso" "$ev" "$c2" "$dom" "$mit" "$zk" >> "$CSV_STATS"
done
echo "    estadisticas generadas"

# 6. Resumen
printf '%b\n' "${CYAN}[6/6] Generando resumen...${NC}"
RESUMEN="$OUT/00_RESUMEN.txt"
{
  echo '======================================================'
  echo ' STEALERLAB - RESUMEN DE TRIAJE'
  echo " Generado: $(date -u '+%Y-%m-%d %H:%M:%S') UTC"
  echo '======================================================'
  echo; echo '--- MUESTRAS ---'; cat "$CSV_MUESTRAS"
  echo; echo '--- INDICADORES DE RED CANDIDATOS ---'; cat "$CSV_C2"
  echo; echo '--- ESTADISTICAS ---'; cat "$CSV_STATS"
  echo; echo '--- ARTEFACTOS OBSERVADOS ---'; head -80 "$CSV_HOST"
  echo; echo '--- PROCESOS CANDIDATOS ---'; head -80 "$CSV_PROC"
  echo; echo 'Nota: candidato no equivale a C2/exfiltracion confirmada. La atribucion requiere correlacion con proceso, destino, ventana temporal y control limpio.'
} > "$RESUMEN"

echo -e "${GREEN}=== TRIAJE COMPLETO ===${NC}"
cat "$RESUMEN"
