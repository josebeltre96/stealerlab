# mitmproxy (sinkhole)

Comando de interceptacion transparente:
```
mitmdump --mode transparent --showhost --ssl-insecure \
  --set block_global=false --set flow_detail=2 \
  -w /var/log/mitm/flows.mitm
```
Nota: `--ssl-insecure` desactiva la verificacion del certificado del servidor upstream
por parte de mitmproxy. La confianza del cliente (victima) se logra instalando la CA
de mitmproxy en su almacen de "Entidades de certificacion raiz de confianza".
