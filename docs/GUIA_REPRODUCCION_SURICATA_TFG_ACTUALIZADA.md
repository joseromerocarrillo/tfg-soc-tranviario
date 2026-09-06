# Guía interna de reproducción — Suricata online + tcpreplay + Wazuh

## 1. Objetivo

Esta guía documenta el procedimiento estable para reproducir los casos prácticos del TFG usando:

- **Suricata en modo online/live**, escuchando tráfico en `eth0` dentro del contenedor `suricata-live`.
- **tcpreplay-sender**, contenedor usado para reinyectar PCAPs contra la red Docker `suricata-lab`.
- **Wazuh Agent**, que monitoriza el fichero `eve.json` generado por Suricata.
- **Wazuh Manager**, que recibe los eventos del agente y eleva/correlaciona las alertas mediante reglas locales.

Flujo esperado:

```text
PCAP sintético/validado
    -> tcpreplay-sender
    -> red Docker suricata-lab
    -> suricata-live
    -> eve.json / fast.log
    -> Wazuh Agent
    -> Wazuh Manager
    -> alerts.json
```

El objetivo de estas pruebas es reproducir los casos en **modo online/live**, no únicamente con análisis offline mediante `suricata -r`.

> Nota importante: el análisis offline se usará solo como diagnóstico para comprobar que un PCAP y una regla son válidos. La demo principal debe hacerse con Suricata escuchando en vivo.

---

## 2. Rutas y ficheros del laboratorio

En Windows:

```text
C:\tfg\suricata\config\suricata.yaml
C:\tfg\suricata\rules\local.rules
C:\tfg\suricata\logs\eve.json
C:\tfg\suricata\logs\fast.log
C:\tfg\suricata\pcaps\
```

En VM Linux / agente Wazuh, si la carpeta de logs está compartida:

```text
/media/sf_logs/eve.json
/media/sf_logs/fast.log
```

PCAPs usados actualmente:

```text
http_en_502.pcap                  # HTTP sobre puerto Modbus 502
ssh_en_8080.pcap                  # SSH fuera de su puerto habitual, sobre 8080
binario_aleatorio_3389.pcap       # Payload binario arbitrario hacia 3389/RDP
escaneo_activos_servicios.pcap    # Caso 6: escaneo vertical + barrido horizontal
ssh_bruteforce_billetaje.pcap     # Caso 7: fuerza bruta SSH
trafico_legitimo.pcapng           # Captura grande original, no usar para replay rápido
```

---

## 3. Configuración final esperada

### 3.1 `suricata.yaml`

Variables relevantes:

```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.2.0/24,192.168.5.0/24,192.168.12.0/24,192.168.16.0/24,192.168.21.0/24]"
    SSH_TARGETS: "[192.168.16.0/24,192.168.12.0/24]"
```

`HOME_NET` incluye las subredes de laboratorio supervisadas.

`SSH_TARGETS` incluye las subredes sobre las que se aplica el caso 7. Actualmente incluye:

```text
192.168.16.0/24
192.168.12.0/24
```

Esto es correcto si el PCAP de fuerza bruta SSH va hacia:

```text
192.168.12.20:22
```

La carga de reglas debe estar así:

```yaml
default-rule-path: /etc/suricata/rules

rule-files:
  - local.rules
```

Salidas esperadas:

```yaml
outputs:
  - fast:
      enabled: yes
      filename: fast.log

  - eve-log:
      enabled: yes
      filename: eve.json
```

Si `eve-log` tiene una sección `types:`, debe incluir `alert`:

```yaml
  - eve-log:
      enabled: yes
      filename: eve.json
      types:
        - alert
        - http
        - flow
        - stats
```

Si no aparece `alert`, Suricata puede registrar `stats`, `flow` o `http`, pero Wazuh no tendrá alertas reales que elevar.

---

### 3.2 `local.rules`

Punto crítico: **cada regla debe estar en una sola línea**.

Suricata rechazó anteriormente reglas multilínea con errores como:

```text
Signature missing required value "sid"
error parsing signature "alert tcp any any -> $SSH_TARGETS 22 ("
```

Por tanto, mantener cada firma completa en una sola línea.

Resumen de SIDs:

```text
5500001 - Protocolo distinto de Modbus en puerto 502
5500002 - Protocolo distinto de HTTP en puerto 80
5500003 - Protocolo distinto de TLS en puerto 443
5500004 - Protocolo distinto de SSH en puerto 22
5500005 - Protocolo distinto de RDP en puerto 3389
5500006 - Modbus fuera del puerto 502
5500007 - SSH fuera del puerto 22
5500008 - Detección de protocolo fallida, posible túnel/ofuscación
5500009 - Discordancia app-layer en ambos sentidos
5500010 - Caso 6, escaneo vertical TCP SYN
5500011 - Caso 6, barrido SYN desde un origen
5500020 - Caso 7, conexiones SSH repetidas desde un origen
5500021 - Caso 7, sesiones SSH identificadas repetidas
```

La exclusión de TCP/22 en las reglas del caso 6 es importante para que la fuerza bruta SSH no se clasifique como escaneo:

```suricata
alert tcp any any -> $HOME_NET !22 (...)
```

Si aparecen warnings de reglas SYN-only, por ejemplo:

```text
W: detect: rule 5500020: SYN-only to port(s) 22:22 w/o direction specified, disabling for toclient direction
```

no significa que Suricata esté fallando. Son avisos sobre dirección de evaluación. Para limpiarlos, se puede añadir `flow:to_server;` en reglas SYN-only cuando proceda.

---

## 4. Procedimiento recomendado desde cero

Usar este procedimiento cuando:

- Se haya recreado algún contenedor.
- Suricata deje de generar alertas en modo live.
- Se hayan hecho muchas pruebas seguidas.
- Se hayan limpiado logs.
- Se cambie `suricata.yaml` o `local.rules`.
- Se quiera preparar una demo limpia.

### 4.1 Parar y eliminar Suricata live

```powershell
docker rm -f suricata-live
```

### 4.2 Limpiar logs sin borrar los ficheros

No borrar `eve.json` mientras Suricata está corriendo. Si se borra el fichero, Suricata puede seguir escribiendo sobre un descriptor antiguo.

Usar:

```powershell
Clear-Content C:\tfg\suricata\logs\eve.json -ErrorAction SilentlyContinue
Clear-Content C:\tfg\suricata\logs\fast.log -ErrorAction SilentlyContinue
```

### 4.3 Arrancar Suricata online

```powershell
docker run -d --name suricata-live `
   --network suricata-lab `
   --cap-add=NET_ADMIN `
   --cap-add=NET_RAW `
   --cap-add=SYS_NICE `
   -v C:\tfg\suricata\config\suricata.yaml:/etc/suricata/suricata.yaml `
   -v C:\tfg\suricata\rules:/etc/suricata/rules `
   -v C:\tfg\suricata\logs:/var/log/suricata `
   jasonish/suricata:latest `
   -c /etc/suricata/suricata.yaml `
   -i eth0 `
   -l /var/log/suricata `
   -k none
```

### 4.4 Comprobar que Suricata está corriendo

```powershell
docker ps
```

### 4.5 Comprobar interfaz

```powershell
docker exec -it suricata-live sh -lc "ip addr show eth0"
```

### 4.6 Comprobar errores de reglas

```powershell
docker logs suricata-live | Select-String "error|Error|Warning|detect-parse|55000"
```

Si aparecen errores `detect-parse`, revisar `local.rules`.

---

## 5. Validación previa de reglas y configuración

Antes de lanzar pruebas, validar la configuración con Suricata en modo test:

```powershell
docker run --rm `
   -v C:\tfg\suricata\config\suricata.yaml:/etc/suricata/suricata.yaml `
   -v C:\tfg\suricata\rules:/etc/suricata/rules `
   -v C:\tfg\suricata\logs:/var/log/suricata `
   jasonish/suricata:latest `
   -T `
   -c /etc/suricata/suricata.yaml `
   -l /var/log/suricata
```

Resultado bueno:

```text
Configuration provided was successfully loaded. Exiting.
```

Los warnings de capacidades en modo test no son críticos:

```text
Warning: no sys_nice capability
Warning: no net_admin capability
Warning: running as root due to missing capabilities
```

En el contenedor real `suricata-live` se usan las capacidades:

```powershell
--cap-add=NET_ADMIN
--cap-add=NET_RAW
--cap-add=SYS_NICE
```

Si el test falla, no iniciar pruebas hasta corregir la regla, variable o ruta indicada.

---

## 6. Red Docker y contenedor de replay

### 6.1 Comprobar que ambos contenedores están en la red correcta

```powershell
docker inspect suricata-live | Select-String "suricata-lab"
docker inspect tcpreplay-sender | Select-String "suricata-lab"
```

También puede comprobarse la red completa:

```powershell
docker network inspect suricata-lab
```

Deben aparecer, al menos:

```text
suricata-live
tcpreplay-sender
```

### 6.2 Crear `tcpreplay-sender` si no existe

```powershell
docker run -dit --name tcpreplay-sender `
  --network suricata-lab `
  --cap-add=NET_ADMIN `
  --cap-add=NET_RAW `
  -v C:\tfg\suricata\pcaps:/pcaps `
  alpine:3.20 sh
```

Las capacidades `NET_ADMIN` y `NET_RAW` son recomendables para evitar problemas al reinyectar paquetes.

---

## 7. Obtención correcta de MACs para `tcprewrite`

Hay que guardar dos MACs:

- `SURIMAC`: MAC de `suricata-live`.
- `SENDERMAC`: MAC de `tcpreplay-sender`.

Opción recomendada:

```powershell
$SURIMAC = (docker exec suricata-live sh -lc "cat /sys/class/net/eth0/address").Trim()
$SENDERMAC = (docker exec tcpreplay-sender sh -lc "cat /sys/class/net/eth0/address").Trim()

echo "SURIMAC=$SURIMAC"
echo "SENDERMAC=$SENDERMAC"
```

Opción alternativa, usando la red concreta `suricata-lab`:

```powershell
$SURIMAC = ((docker inspect suricata-live | ConvertFrom-Json)[0].NetworkSettings.Networks.'suricata-lab'.MacAddress).Trim()

$SENDERMAC = ((docker inspect tcpreplay-sender | ConvertFrom-Json)[0].NetworkSettings.Networks.'suricata-lab'.MacAddress).Trim()

echo "SURIMAC=$SURIMAC"
echo "SENDERMAC=$SENDERMAC"
```

Puntos críticos:

```text
1. Recalcular MACs cada vez que se recree suricata-live o tcpreplay-sender.
2. Ejecutar el comando de reinyección desde la misma terminal PowerShell donde se definieron $SURIMAC y $SENDERMAC.
3. Las variables de PowerShell solo existen en esa pestaña/sesión.
```

Comprobar el PCAP reescrito:

```powershell
docker exec -it tcpreplay-sender sh -lc "tcpdump -enn -r /tmp/replay.pcap | head -20"
```

Debe verse:

```text
SENDERMAC > SURIMAC
```

Ejemplo:

```text
2a:f7:69:5f:cf:60 > 16:3b:aa:f7:6a:c8
```

---

## 8. Regla crítica sobre velocidad de replay

### 8.1 Valor recomendado

Para las pruebas live del TFG, usar por defecto:

```text
--pps=200
```

Este valor se ha validado como estable: Suricata genera correctamente los eventos `event_type:"alert"` en `eve.json` y Wazuh Manager recibe las alertas.

### 8.2 Valor no recomendado por defecto

No usar como valor por defecto:

```text
--pps=2000
```

Problema observado:

```text
- tcpreplay indica que envía paquetes correctamente.
- Suricata puede ver tráfico con tcpdump.
- El análisis offline con suricata -r genera alertas.
- Pero Suricata online/live no siempre genera event_type:"alert" en eve.json.
- Al bajar a --pps=200, las alertas vuelven a generarse correctamente y llegan a Wazuh Manager.
```

Conclusión:

```text
Para demo y reproducción estable: --pps=200.
Si sigue fallando: probar --pps=50.
Evitar --pps=2000 en la demo final.
```

---

## 9. Comando genérico de reinyección

Desde PowerShell, con Suricata ya levantado y las MACs cargadas en la misma terminal:

```powershell
docker exec -it tcpreplay-sender sh -lc "apk add --no-cache tcpreplay >/dev/null 2>&1 || true && tcprewrite --enet-dmac=$SURIMAC --enet-smac=$SENDERMAC --fixcsum --infile=/pcaps/NOMBRE_DEL_PCAP.pcap --outfile=/tmp/replay.pcap && tcpreplay --intf1=eth0 --pps=200 /tmp/replay.pcap"
```

Si se quiere repetir el mismo PCAP ya reescrito:

```powershell
docker exec -it tcpreplay-sender sh -lc "tcpreplay --intf1=eth0 --pps=200 /tmp/replay.pcap"
```

Si Suricata no genera alertas en live aunque offline sí lo haga:

```powershell
docker exec -it tcpreplay-sender sh -lc "tcpreplay --intf1=eth0 --pps=50 /tmp/replay.pcap"
```

---

## 10. Monitorización de Suricata

### 10.1 En Windows

Ver alertas nuevas:

```powershell
Get-Content C:\tfg\suricata\logs\eve.json -Wait | Select-String '"event_type":"alert"'
```

Buscar SIDs concretos:

```powershell
Get-Content C:\tfg\suricata\logs\eve.json | Select-String '"signature_id":5500001|"signature_id":5500007|"signature_id":5500008|"signature_id":5500010|"signature_id":5500011|"signature_id":5500020|"signature_id":5500021'
```

Ver `fast.log`:

```powershell
Get-Content C:\tfg\suricata\logs\fast.log -Tail 30
```

Buscar SID concreto en `eve.json`:

```powershell
Get-Content C:\tfg\suricata\logs\eve.json -Tail 200 | Select-String '5500001'
```

### 10.2 En Linux / VM2

Si los logs están montados en `/media/sf_logs`:

```bash
tail -n 0 -f /media/sf_logs/eve.json | jq -c 'select(.event_type=="alert") | {sid:.alert.signature_id, sig:.alert.signature, src:.src_ip, dst:.dest_ip, dport:.dest_port, proto:.app_proto}'
```

Comprobar alertas ya existentes:

```bash
cat /media/sf_logs/eve.json | jq -c 'select(.event_type=="alert") | {sid:.alert.signature_id, sig:.alert.signature, src:.src_ip, dst:.dest_ip, dport:.dest_port, proto:.app_proto}' | tail
```

Buscar SID concreto:

```bash
grep '"event_type":"alert"' /media/sf_logs/eve.json | grep '5500001' | tail -5
```

---

## 11. Monitorización en Wazuh

### 11.1 En Wazuh Agent

Comprobar que el agente monitoriza `eve.json`:

```bash
grep -nA5 -B2 "eve.json" /var/ossec/etc/ossec.conf
```

Bloque esperado:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/media/sf_logs/eve.json</location>
</localfile>
```

Comprobar que `logcollector` analiza el fichero:

```bash
grep -i "eve.json\|logcollector\|error" /var/ossec/logs/ossec.log | tail -50
```

Buscar una línea similar a:

```text
Analyzing file: '/media/sf_logs/eve.json'
```

Reiniciar agente:

```bash
/var/ossec/bin/wazuh-control restart
```

O, si está con systemd:

```bash
systemctl restart wazuh-agent
```

### 11.2 En Wazuh Manager

Ver alertas OT:

```bash
tail -f /var/ossec/logs/alerts/alerts.json | jq -c 'select((.rule.id|tostring)|test("^(10005|10006|10007)")) | {id:.rule.id, desc:.rule.description, src:.data.src_ip, dst:.data.dest_ip, sid:.data.alert.signature_id}'
```

IDs esperados:

```text
10005x / 10006x / 10007x según familias de reglas Wazuh configuradas.
100060 - OT-SCAN
100070 - OT-SSH
100071 - OT-SSH elevado por horario no operativo
```

Para buscar fuerza bruta SSH:

```bash
tail -f /var/ossec/logs/alerts/alerts.json | jq -c 'select((.rule.id|tostring)|test("100070|100071")) | {id:.rule.id, desc:.rule.description, src:.data.src_ip, dst:.data.dest_ip, sid:.data.alert.signature_id}'
```

### 11.3 Comprobar si el Manager recibe eventos aunque no los alerte

Activar temporalmente en `/var/ossec/etc/ossec.conf` del Manager:

```xml
<logall_json>yes</logall_json>
```

Reiniciar Manager:

```bash
systemctl restart wazuh-manager
```

Ver eventos en `archives.json`:

```bash
tail -f /var/ossec/logs/archives/archives.json | jq -c 'select(.data.event_type=="alert") | {agent:.agent.name, sid:.data.alert.signature_id, sig:.data.alert.signature, src:.data.src_ip, dst:.data.dest_ip, dport:.data.dest_port}'
```

Interpretación:

```text
Si aparece en archives.json pero no en alerts.json:
  El agente envía el evento, pero las reglas Wazuh no hacen match.

Si no aparece en archives.json:
  El agente no está enviando el evento al Manager o no está leyendo eve.json.
```

---

## 12. Casos de prueba y comandos

### Tabla resumen

| Caso | PCAP | SID Suricata esperado | Regla Wazuh esperada | Replay recomendado |
|---|---|---:|---:|---|
| Caso 5b.1 - HTTP sobre Modbus | `http_en_502.pcap` | `5500001` | Familia `10005x` | `--pps=200` |
| Caso 5b.2 - SSH en 8080 | `ssh_en_8080.pcap` | `5500007` | Familia `10005x` | `--pps=200` |
| Caso 5b.3 - Binario hacia RDP | `binario_aleatorio_3389.pcap` | `5500008` | Familia `10005x` | `--pps=200` |
| Caso 6 - Escaneo activos/servicios | `escaneo_activos_servicios.pcap` | `5500010`, `5500011` | `100060` | `--pps=200` |
| Caso 7 - Fuerza bruta SSH | `ssh_bruteforce_billetaje.pcap` | `5500020`, `5500021` | `100070` / `100071` | `--pps=200` |

---

### 12.1 Caso 5b.1 — HTTP sobre puerto Modbus 502

PCAP:

```text
http_en_502.pcap
```

Reinyección:

```powershell
docker exec -it tcpreplay-sender sh -lc "apk add --no-cache tcpreplay >/dev/null 2>&1 || true && tcprewrite --enet-dmac=$SURIMAC --enet-smac=$SENDERMAC --fixcsum --infile=/pcaps/http_en_502.pcap --outfile=/tmp/replay.pcap && tcpreplay --intf1=eth0 --pps=200 /tmp/replay.pcap"
```

Alerta esperada:

```text
5500001 - OT-DPI protocolo distinto de Modbus en puerto 502
```

Comprobación rápida:

```powershell
Get-Content C:\tfg\suricata\logs\eve.json -Tail 200 | Select-String '5500001'
```

---

### 12.2 Caso 5b.2 — SSH fuera de su puerto habitual, sobre 8080

PCAP:

```text
ssh_en_8080.pcap
```

Reinyección:

```powershell
docker exec -it tcpreplay-sender sh -lc "apk add --no-cache tcpreplay >/dev/null 2>&1 || true && tcprewrite --enet-dmac=$SURIMAC --enet-smac=$SENDERMAC --fixcsum --infile=/pcaps/ssh_en_8080.pcap --outfile=/tmp/replay.pcap && tcpreplay --intf1=eth0 --pps=200 /tmp/replay.pcap"
```

Alerta esperada:

```text
5500007 - OT-DPI SSH fuera del puerto 22
```

Comprobación rápida:

```powershell
Get-Content C:\tfg\suricata\logs\eve.json -Tail 200 | Select-String '5500007'
```

---

### 12.3 Caso 5b.3 — Túnel/ofuscación: binario arbitrario hacia RDP/3389

PCAP:

```text
binario_aleatorio_3389.pcap
```

Reinyección:

```powershell
docker exec -it tcpreplay-sender sh -lc "apk add --no-cache tcpreplay >/dev/null 2>&1 || true && tcprewrite --enet-dmac=$SURIMAC --enet-smac=$SENDERMAC --fixcsum --infile=/pcaps/binario_aleatorio_3389.pcap --outfile=/tmp/replay.pcap && tcpreplay --intf1=eth0 --pps=200 /tmp/replay.pcap"
```

Alerta esperada:

```text
5500008 - OT-DPI detección de protocolo fallida
```

Comprobación rápida:

```powershell
Get-Content C:\tfg\suricata\logs\eve.json -Tail 200 | Select-String '5500008'
```

---

### 12.4 Caso 6 — Escaneo de activos y servicios

PCAP:

```text
escaneo_activos_servicios.pcap
```

Contenido:

```text
Escaneo vertical:
192.168.21.24 -> 192.168.2.10, puertos TCP 1-1000

Barrido horizontal:
192.168.21.24 -> 192.168.2.0/24, ICMP + SYN contra servicios comunes
```

Reinyección:

```powershell
docker exec -it tcpreplay-sender sh -lc "apk add --no-cache tcpreplay >/dev/null 2>&1 || true && tcprewrite --enet-dmac=$SURIMAC --enet-smac=$SENDERMAC --fixcsum --infile=/pcaps/escaneo_activos_servicios.pcap --outfile=/tmp/replay.pcap && tcpreplay --intf1=eth0 --pps=200 /tmp/replay.pcap"
```

Alertas esperadas:

```text
5500010 - OT-SCAN posible escaneo vertical TCP SYN
5500011 - OT-SCAN barrido SYN desde un origen
```

Correlación esperada en Wazuh:

```text
100060 - OT-SCAN
```

Nota: las reglas del caso 6 excluyen `TCP/22` para evitar que la fuerza bruta SSH se clasifique como escaneo.

Comprobación rápida:

```powershell
Get-Content C:\tfg\suricata\logs\eve.json -Tail 200 | Select-String '5500010|5500011'
```

---

### 12.5 Caso 7 — Fuerza bruta SSH

PCAP:

```text
ssh_bruteforce_billetaje.pcap
```

Contenido:

```text
Origen: 192.168.21.24
Destino: 192.168.12.20:22
Patrón: muchas conexiones SSH cortas/repetidas
```

Reinyección:

```powershell
docker exec -it tcpreplay-sender sh -lc "apk add --no-cache tcpreplay >/dev/null 2>&1 || true && tcprewrite --enet-dmac=$SURIMAC --enet-smac=$SENDERMAC --fixcsum --infile=/pcaps/ssh_bruteforce_billetaje.pcap --outfile=/tmp/replay.pcap && tcpreplay --intf1=eth0 --pps=200 /tmp/replay.pcap"
```

Alertas esperadas:

```text
5500020 - OT-SSH conexiones SSH repetidas desde un origen
5500021 - OT-SSH sesiones SSH identificadas repetidas
```

La principal es `5500020`, porque detecta el patrón de muchas conexiones TCP/22.

La `5500021` depende de que Suricata identifique el app-layer como SSH.

Correlación esperada en Wazuh:

```text
100070 - OT-SSH
```

Comprobación rápida:

```powershell
Get-Content C:\tfg\suricata\logs\eve.json -Tail 200 | Select-String '5500020|5500021'
```

#### Elevación por horario no operativo

La regla Wazuh `100071` evalúa la hora real del Wazuh Manager al procesar el evento, no la marca temporal interna del PCAP.

Opciones:

```text
Opción A:
Reinyectar durante la ventana nocturna real configurada, por ejemplo 20:00-07:00.

Opción B:
Para una demo durante el día, ampliar temporalmente el elemento <time> de la regla 100071,
reinyectar el PCAP, verificar la alerta y revertir el cambio.
```

---

## 13. Comprobaciones rápidas de PCAP

Ver destino/puerto del PCAP SSH:

```powershell
docker exec -it tcpreplay-sender sh -lc "apk add --no-cache tcpdump >/dev/null 2>&1 || true && tcpdump -nn -r /pcaps/ssh_bruteforce_billetaje.pcap 'tcp port 22' | head -20"
```

Ver el PCAP de escaneo:

```powershell
docker exec -it tcpreplay-sender sh -lc "apk add --no-cache tcpdump >/dev/null 2>&1 || true && tcpdump -nn -r /pcaps/escaneo_activos_servicios.pcap | head -50"
```

Ver HTTP sobre 502:

```powershell
docker exec -it tcpreplay-sender sh -lc "apk add --no-cache tcpdump >/dev/null 2>&1 || true && tcpdump -nn -A -r /pcaps/http_en_502.pcap 'tcp port 502' | head -80"
```

Ver SSH sobre 8080:

```powershell
docker exec -it tcpreplay-sender sh -lc "apk add --no-cache tcpdump >/dev/null 2>&1 || true && tcpdump -nn -A -r /pcaps/ssh_en_8080.pcap 'tcp port 8080' | head -80"
```

---

## 14. Prueba offline de diagnóstico

Usar esta prueba cuando:

```text
- Suricata live ve tráfico pero no genera alertas.
- Wazuh no recibe nada y no se sabe si el problema está en Suricata o Wazuh.
- Se quiere validar que el PCAP y la regla son correctos.
```

Ejemplo con `http_en_502.pcap`:

```powershell
New-Item -ItemType Directory -Force C:\tfg\suricata\logs\offline_test | Out-Null
Clear-Content C:\tfg\suricata\logs\offline_test\eve.json -ErrorAction SilentlyContinue
Clear-Content C:\tfg\suricata\logs\offline_test\fast.log -ErrorAction SilentlyContinue

docker run --rm `
  -v C:\tfg\suricata\config\suricata.yaml:/etc/suricata/suricata.yaml `
  -v C:\tfg\suricata\rules:/etc/suricata/rules `
  -v C:\tfg\suricata\logs\offline_test:/var/log/suricata `
  -v C:\tfg\suricata\pcaps:/pcaps `
  jasonish/suricata:latest `
  -r /pcaps/http_en_502.pcap `
  -c /etc/suricata/suricata.yaml `
  -l /var/log/suricata `
  -k none
```

Comprobar alertas offline:

```powershell
Get-Content C:\tfg\suricata\logs\offline_test\eve.json | Select-String '"event_type":"alert"'
Get-Content C:\tfg\suricata\logs\offline_test\fast.log -Tail 30
```

Interpretación:

```text
Si offline genera alertas:
  - PCAP correcto.
  - Reglas correctas.
  - suricata.yaml correcto.
  - El problema está en modo live, velocidad de replay, MACs, estado interno o monitorización.

Si offline no genera alertas:
  - Revisar regla, HOME_NET, app-layer, SID o PCAP.
```

Caso observado:

```text
Offline generaba alertas correctamente.
Online a --pps=2000 no generaba alertas fiables.
Online a --pps=200 generó alertas correctamente y llegaron a Wazuh Manager.
```

---

## 15. Troubleshooting

### 15.1 Suricata no arranca o no carga reglas

Comando:

```powershell
docker logs suricata-live | Select-String "error|Error|Warning|detect-parse"
```

Causa habitual:

```text
Reglas Suricata multilínea.
```

Solución:

```text
Dejar cada firma completa en una sola línea.
```

---

### 15.2 El tráfico se inyecta pero Suricata no ve paquetes

Comprobar que Suricata y `tcpreplay-sender` están en la misma red:

```powershell
docker inspect suricata-live | Select-String "suricata-lab"
docker inspect tcpreplay-sender | Select-String "suricata-lab"
```

Comprobar comunicación básica:

```powershell
$SURIIP = (docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" suricata-live).Trim()
echo "SURIIP=$SURIIP"
docker exec -it tcpreplay-sender ping -c 3 $SURIIP
```

En otra terminal:

```powershell
docker exec -it suricata-live sh -lc "tcpdump -i eth0 -nn -e -c 20"
```

Si Suricata no ve ni el ping, el problema es de red Docker o captura.

---

### 15.3 Suricata ve tráfico pero no genera alertas online

Comprobar primero si offline genera alertas.

Si offline funciona, aplicar:

```text
1. Parar y recrear suricata-live.
2. Limpiar eve.json y fast.log con Clear-Content.
3. Recalcular SURIMAC y SENDERMAC.
4. Reinyectar desde la misma terminal PowerShell.
5. Usar --pps=200.
6. Si sigue fallando, usar --pps=50.
```

Comando de recuperación rápida:

```powershell
docker rm -f suricata-live

Clear-Content C:\tfg\suricata\logs\eve.json -ErrorAction SilentlyContinue
Clear-Content C:\tfg\suricata\logs\fast.log -ErrorAction SilentlyContinue

docker run -d --name suricata-live `
   --network suricata-lab `
   --cap-add=NET_ADMIN `
   --cap-add=NET_RAW `
   --cap-add=SYS_NICE `
   -v C:\tfg\suricata\config\suricata.yaml:/etc/suricata/suricata.yaml `
   -v C:\tfg\suricata\rules:/etc/suricata/rules `
   -v C:\tfg\suricata\logs:/var/log/suricata `
   jasonish/suricata:latest `
   -c /etc/suricata/suricata.yaml `
   -i eth0 `
   -l /var/log/suricata `
   -k none

$SURIMAC = (docker exec suricata-live sh -lc "cat /sys/class/net/eth0/address").Trim()
$SENDERMAC = (docker exec tcpreplay-sender sh -lc "cat /sys/class/net/eth0/address").Trim()

echo "SURIMAC=$SURIMAC"
echo "SENDERMAC=$SENDERMAC"
```

Después reinyectar con:

```powershell
docker exec -it tcpreplay-sender sh -lc "tcprewrite --enet-dmac=$SURIMAC --enet-smac=$SENDERMAC --fixcsum --infile=/pcaps/http_en_502.pcap --outfile=/tmp/replay.pcap && tcpreplay --intf1=eth0 --pps=200 /tmp/replay.pcap"
```

---

### 15.4 Suricata genera alertas pero Wazuh no las muestra

Primero confirmar que existen alertas reales en `eve.json`:

```powershell
Get-Content C:\tfg\suricata\logs\eve.json | Select-String '"event_type":"alert"'
```

Si existen, comprobar en el agente:

```bash
grep -nA5 -B2 "eve.json" /var/ossec/etc/ossec.conf
grep -i "eve.json\|logcollector\|error" /var/ossec/logs/ossec.log | tail -50
```

Comprobar que el agente está activo en el Manager:

```bash
/var/ossec/bin/agent_control -lc
```

Si se activa `logall_json`, comprobar `archives.json`:

```bash
tail -f /var/ossec/logs/archives/archives.json | grep '5500001'
```

Interpretación:

```text
Aparece en archives.json pero no en alerts.json:
  Problema de reglas Wazuh.

No aparece en archives.json:
  Problema de agente, ruta, permisos o conexión Agent -> Manager.
```

---

### 15.5 El `eve.json` parece no actualizarse

No borrar el fichero con Suricata corriendo.

Usar:

```powershell
Clear-Content C:\tfg\suricata\logs\eve.json -ErrorAction SilentlyContinue
Clear-Content C:\tfg\suricata\logs\fast.log -ErrorAction SilentlyContinue
```

O reiniciar Suricata con el procedimiento limpio.

---

### 15.6 Hay eventos `stats`, pero no `alert`

Un evento `stats` no es una alerta de Suricata consumible como alerta OT por Wazuh.

Buscar específicamente:

```powershell
Get-Content C:\tfg\suricata\logs\eve.json | Select-String '"event_type":"alert"'
```

Si solo hay:

```json
"event_type":"stats"
```

entonces Suricata está escribiendo estadísticas, pero no hay alertas reales en el fichero.

---

### 15.7 Saltan alertas de escaneo en vez de SSH

Causa:

```text
Las reglas 5500010/5500011 capturan también TCP/22.
```

Solución:

```text
Mantener el destino de las reglas de escaneo como $HOME_NET !22.
```

---

### 15.8 5500020 no salta

Comprobar:

```text
1. El PCAP va realmente a 192.168.12.20:22.
2. SSH_TARGETS contiene 192.168.12.0/24.
3. La regla 5500020 está cargada sin errores.
4. El replay usa MACs correctas.
5. La velocidad de replay es --pps=200.
```

Comandos:

```powershell
docker exec -it suricata-live sh -lc "grep -n 'SSH_TARGETS' /etc/suricata/suricata.yaml"
docker exec -it suricata-live sh -lc "grep -R '5500020\|5500021' -n /etc/suricata/rules"
docker logs suricata-live | Select-String "5500020|5500021|error|Error|Warning|detect-parse"
```

---

## 16. Checklist antes de cada demo

```text
[ ] suricata-live eliminado y recreado si había cambios de configuración o fallos de alertas.
[ ] eve.json y fast.log limpiados con Clear-Content.
[ ] docker ps muestra suricata-live y tcpreplay-sender.
[ ] suricata-live y tcpreplay-sender están en la red suricata-lab.
[ ] docker logs suricata-live no muestra detect-parse.
[ ] SURIMAC y SENDERMAC recalculadas después de recrear contenedores.
[ ] Estoy usando la misma terminal PowerShell donde se definieron $SURIMAC y $SENDERMAC.
[ ] PCAP correcto seleccionado.
[ ] Se usa --pps=200 como velocidad recomendada.
[ ] No se usa --pps=2000 para la demo final.
[ ] Se abre la monitorización de eve.json antes de reinyectar.
[ ] Se verifican SIDs en eve.json.
[ ] Se verifican alertas en Wazuh Manager.
[ ] Si algo falla, se prueba offline para separar problema de regla/PCAP vs problema live.
```

---

## 17. Procedimiento rápido de recuperación

Si algo deja de funcionar y no se sabe por qué, ejecutar exactamente:

```powershell
docker rm -f suricata-live

Clear-Content C:\tfg\suricata\logs\eve.json -ErrorAction SilentlyContinue
Clear-Content C:\tfg\suricata\logs\fast.log -ErrorAction SilentlyContinue

docker run -d --name suricata-live `
   --network suricata-lab `
   --cap-add=NET_ADMIN `
   --cap-add=NET_RAW `
   --cap-add=SYS_NICE `
   -v C:\tfg\suricata\config\suricata.yaml:/etc/suricata/suricata.yaml `
   -v C:\tfg\suricata\rules:/etc/suricata/rules `
   -v C:\tfg\suricata\logs:/var/log/suricata `
   jasonish/suricata:latest `
   -c /etc/suricata/suricata.yaml `
   -i eth0 `
   -l /var/log/suricata `
   -k none

$SURIMAC = (docker exec suricata-live sh -lc "cat /sys/class/net/eth0/address").Trim()
$SENDERMAC = (docker exec tcpreplay-sender sh -lc "cat /sys/class/net/eth0/address").Trim()

echo "SURIMAC=$SURIMAC"
echo "SENDERMAC=$SENDERMAC"
```

Abrir monitorización:

```powershell
Get-Content C:\tfg\suricata\logs\eve.json -Wait | Select-String '"event_type":"alert"'
```

Reinyectar:

```powershell
docker exec -it tcpreplay-sender sh -lc "tcprewrite --enet-dmac=$SURIMAC --enet-smac=$SENDERMAC --fixcsum --infile=/pcaps/http_en_502.pcap --outfile=/tmp/replay.pcap && tcpreplay --intf1=eth0 --pps=200 /tmp/replay.pcap"
```

---

## 18. Elementos pendientes o a completar

1. Añadir una sección específica para `movimiento_lateral.pcap` si corresponde a otro caso del TFG.
2. Confirmar si se quiere demostrar la escalabilidad de `SSH_TARGETS` con:

```yaml
SSH_TARGETS: "$HOME_NET"
```

o con:

```yaml
SSH_TARGETS: "[192.168.0.0/16]"
```

3. Para futuras pruebas de protocolos fuera de puerto, validar en `eve.json` que Suricata identifica `app_proto` como se espera.
4. Mantener una tabla final de correspondencia entre:
   - caso de uso,
   - PCAP,
   - SID Suricata esperado,
   - regla Wazuh esperada,
   - comando de replay.
