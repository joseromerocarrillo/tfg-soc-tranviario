# Guía de resolución de problemas del laboratorio

Esta guía reúne los errores y situaciones de diagnóstico observados durante la implementación y validación del laboratorio del TFG.

No sustituye al script principal de ejecución de casos. Para lanzar las pruebas se debe utilizar `scripts/Invoke-CasosPracticos.ps1` y la guía de ejecución rápida asociada. Este documento se centra únicamente en **síntomas, causas probables, comprobaciones y soluciones**.

> **Alcance:** laboratorio académico con Wazuh, Suricata, Zeek, Conpot, Docker Desktop, máquinas virtuales Ubuntu y host Windows.

---

## 1. Criterio de diagnóstico

Antes de modificar reglas o configuraciones, identificar en qué punto se rompe la cadena:

```text
generación del estímulo
        ↓
sensor / servicio
        ↓
log local
        ↓
Wazuh Agent o syslog
        ↓
Wazuh Manager
        ↓
alerts.json
        ↓
Dashboard
```

La regla general es comprobar cada nivel antes de pasar al siguiente.

### Casos basados en análisis pasivo

Los casos 2, 3, 5b, 6 y 7 pueden validarse mediante tráfico reinyectado porque Zeek o Suricata actúan como sensores pasivos.

```text
PCAP sintético
→ tcprewrite
→ tcpreplay
→ Zeek / Suricata
→ notice.log / eve.json
→ Wazuh
```

### Casos que requieren una interacción real

Los casos 1, 4 y 5 necesitan una acción real sobre el servicio o el host:

- Caso 1: interacción Modbus real contra Conpot.
- Caso 4: `PUT` FTP real que cree o modifique un fichero.
- Caso 5: autenticación SSH real en el host monitorizado.

`tcpreplay` no crea una sesión TCP completa contra un servicio ni modifica el estado del sistema de archivos. Por tanto, no debe utilizarse como sustituto de estas interacciones.

---

# 2. PowerShell

## 2.1 PowerShell bloquea `Invoke-CasosPracticos.ps1`

### Síntoma

```text
El archivo ... no está firmado digitalmente.
PSSecurityException
```

### Solución temporal recomendada

Aplicar el cambio únicamente a la sesión actual:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

Después:

```powershell
.\Invoke-CasosPracticos.ps1
```

El cambio desaparece al cerrar esa consola.

---

# 3. Suricata

## 3.1 Suricata no arranca o rechaza una regla

### Síntomas habituales

```text
Signature missing required value "sid"
```

o:

```text
error parsing signature
detect-parse
```

### Causa observada

Una firma de `local.rules` estaba dividida en varias líneas o tenía sintaxis incompleta.

### Diagnóstico

```powershell
docker logs suricata-live |
  Select-String "error|Error|Warning|detect-parse"
```

También puede validarse la configuración sin arrancar el sensor:

```powershell
docker run --rm `
  -v C:\tfg\suricata\config\suricata.yaml:/etc/suricata/suricata.yaml `
  -v C:\tfg\suricata\rules:/etc/suricata/rules `
  jasonish/suricata:latest `
  -T `
  -c /etc/suricata/suricata.yaml
```

Resultado esperado:

```text
Configuration provided was successfully loaded. Exiting.
```

### Solución

Mantener cada firma Suricata completa en una sola línea y corregir la regla indicada por `detect-parse`.

---

## 3.2 Aparece un warning `SYN-only`

### Ejemplo

```text
SYN-only to port(s) ... disabling for toclient direction
```

### Interpretación

No implica necesariamente que Suricata haya fallado. Es un aviso sobre la dirección en la que se evalúa una regla basada únicamente en SYN.

Cuando proceda, puede utilizarse:

```text
flow:to_server;
```

No modificar una regla que ya está validada solo para eliminar un warning cosmético.

---

## 3.3 `tcpreplay` envía paquetes pero Suricata no los ve

### Comprobar la red Docker

```powershell
docker inspect suricata-live | Select-String "suricata-lab"
docker inspect tcpreplay-sender | Select-String "suricata-lab"
docker network inspect suricata-lab
```

Los dos contenedores deben pertenecer a `suricata-lab`.

### Comprobar captura directa

En otra consola:

```powershell
docker exec -it suricata-live sh -lc "tcpdump -i eth0 -nn -e -c 20"
```

Si no se observan los paquetes reinyectados, revisar la red Docker y las direcciones MAC utilizadas por `tcprewrite`.

---

## 3.4 Suricata no recibe el PCAP después de recrear los contenedores

Las direcciones MAC de los contenedores pueden cambiar al recrearlos.

### Recalcular siempre

```powershell
$SURIMAC = (docker exec suricata-live sh -lc "cat /sys/class/net/eth0/address").Trim()
$SENDERMAC = (docker exec tcpreplay-sender sh -lc "cat /sys/class/net/eth0/address").Trim()

"Suricata: $SURIMAC"
"Sender:    $SENDERMAC"
```

### Puntos críticos

1. Recalcular las MAC después de recrear `suricata-live` o `tcpreplay-sender`.
2. Ejecutar la reinyección desde la **misma sesión PowerShell** donde se definieron las variables.
3. Reescribir el PCAP con la MAC destino del sensor.

---

## 3.5 Suricata ve tráfico, pero no genera alertas en modo live

Este fue uno de los problemas más importantes observados durante las pruebas.

### Diagnóstico

Comprobar primero el mismo PCAP en modo offline.

Si offline genera alertas pero live no:

- el PCAP es válido;
- la firma es válida;
- el problema se encuentra en la entrega live, el ritmo de replay o el estado del sensor.

### Velocidad validada

Utilizar por defecto:

```text
--pps=200
```

Se observó que:

```text
--pps=2000
```

podía reinyectar correctamente y ser visible mediante `tcpdump`, pero no generar de forma fiable todos los eventos `alert` en `eve.json`.

Si a 200 pps continúa el problema:

```text
--pps=50
```

### Recuperación

1. Recrear `suricata-live`.
2. Vaciar los logs sin borrarlos.
3. Recalcular las MAC.
4. Reinyectar a 200 pps.
5. Si es necesario, repetir a 50 pps.

---

## 3.6 `eve.json` no parece actualizarse

No borrar `eve.json` mientras Suricata mantiene el fichero abierto.

Usar:

```powershell
Clear-Content C:\tfg\suricata\logs\eve.json -ErrorAction SilentlyContinue
Clear-Content C:\tfg\suricata\logs\fast.log -ErrorAction SilentlyContinue
```

Si el comportamiento continúa, recrear el contenedor Suricata.

---

## 3.7 `eve.json` contiene `stats`, pero no alertas

Un evento:

```json
"event_type":"stats"
```

no es una alerta IDS.

Comprobar específicamente:

```powershell
Get-Content C:\tfg\suricata\logs\eve.json |
  Select-String '"event_type":"alert"'
```

Si no aparecen eventos `alert`:

1. validar la regla;
2. revisar `HOME_NET`;
3. comprobar el PCAP;
4. ejecutar el análisis offline;
5. revisar MAC y velocidad si offline sí funciona.

---

## 3.8 Suricata genera alertas pero Wazuh no las muestra

### Paso 1 — confirmar `eve.json`

```powershell
Get-Content C:\tfg\suricata\logs\eve.json |
  Select-String '"event_type":"alert"'
```

### Paso 2 — comprobar el Wazuh Agent

```bash
grep -nA5 -B2 "eve.json" /var/ossec/etc/ossec.conf
grep -i "eve.json\|logcollector\|error" /var/ossec/logs/ossec.log | tail -50
```

Debe existir un bloque equivalente a:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/media/sf_logs/eve.json</location>
</localfile>
```

### Paso 3 — comprobar recepción en el Manager

Si `logall_json` está activo:

```bash
tail -f /var/ossec/logs/archives/archives.json
```

Interpretación:

```text
Evento en archives.json pero no en alerts.json
→ revisar reglas Wazuh.

Evento ausente también en archives.json
→ revisar agente, logcollector, permisos, ruta y conexión con el Manager.
```

---

## 3.9 La fuerza bruta SSH se clasifica también como escaneo

Las reglas del Caso 6 deben evitar que el tráfico TCP/22 del Caso 7 se absorba como escaneo.

Comprobar que la regla correspondiente excluye TCP/22 según la configuración validada.

---

# 4. Zeek

## 4.1 Zeek funciona offline pero no genera `notice.log` en live

Este patrón suele indicar un problema de entrega del tráfico, no del script Zeek.

### Comprobar

1. `zeek-live` y `tcpreplay-sender` están en `suricata-lab`.
2. Se ha recalculado `ZEEKMAC`.
3. `tcprewrite` utiliza esa MAC como destino.
4. La reinyección se ejecuta desde la misma sesión PowerShell.
5. Se utiliza un ritmo estable de replay.

### MAC del sensor

```powershell
$ZEEKMAC = (docker exec zeek-live sh -lc "cat /sys/class/net/eth0/address").Trim()
$SENDERMAC = (docker exec tcpreplay-sender sh -lc "cat /sys/class/net/eth0/address").Trim()
```

Si el análisis offline genera la notificación esperada y live no, revisar primero MAC, red Docker y velocidad de replay.

---

## 4.2 Wazuh recibe la notificación Zeek pero el filtro `jq` muestra IP nula

Según el decodificado JSON, los campos pueden quedar anidados.

En las alertas validadas del Caso 2 aparecen tanto:

```text
data.src
data.dst
```

como:

```text
data.id.orig_h
data.id.resp_h
```

Un filtro de comprobación robusto puede utilizar:

```bash
jq -c '
  select(.rule.id? == "100020" or .rule.id? == "100021" or .rule.id? == "100022")
  |
  {
    id: .rule.id,
    src: (.data.src // .data.id.orig_h),
    dst: (.data.dst // .data.id.resp_h),
    note: .data.note
  }
' /var/ossec/logs/alerts/alerts.json
```

Un valor nulo en un filtro mal construido no implica que Wazuh haya perdido la dirección IP.

---

# 5. Conpot

## 5.1 El nombre `conpot-scada` ya está en uso

### Síntoma

```text
Conflict. The container name "/conpot-scada" is already in use
```

### Diagnóstico

```powershell
docker ps -a --filter "name=conpot-scada"
```

### Solución

```powershell
docker rm -f conpot-scada
```

y volver a crearlo.

---

## 5.2 Conpot termina con `Exit 127` / `conpot: not found`

### Síntoma

```text
Exited (127)
sh: conpot: not found
```

### Causa observada

Se intentó sustituir el comando de arranque de la imagen y ejecutar manualmente un binario que no estaba disponible de esa forma en el `PATH`.

### Solución

Utilizar el comando de arranque proporcionado por la imagen validada en el laboratorio, salvo que se conozca exactamente el `ENTRYPOINT` utilizado.

---

## 5.3 Conpot no responde en el puerto esperado

En la imagen utilizada durante las pruebas, el mapeo validado fue:

```text
host 502  → contenedor 5020
host 8080 → contenedor 8800
```

Ejemplo:

```powershell
docker run -d --name conpot-scada `
  -p 502:5020 `
  -p 8080:8800 `
  honeynet/conpot:latest
```

No asumir que el puerto interno es el mismo que el publicado en el host.

---

## 5.4 `Invalid address` en el cliente Modbus

### Ejemplo

```text
0: Invalid address
```

No implica que el Caso 1 haya fallado.

La interacción puede generar correctamente:

- conexión Modbus;
- tráfico Modbus;
- excepción Modbus.

En la validación, la excepción `Modbus Error: Exception code = 2` fue incluso utilizada como evidencia del procesamiento realizado por Conpot/Wazuh.

---

## 5.5 Wazuh no recibe el syslog de Conpot

En esta arquitectura, Wazuh ve el syslog procedente del host Windows/Docker Desktop:

```text
192.168.56.1
```

y no necesariamente la dirección interna que Conpot observa para el cliente dentro de Docker.

Comprobar:

```bash
sudo tcpdump -ni any udp port 514 -A
```

y:

```bash
sudo ss -lunp | grep ':514'
```

La lista `allowed-ips` del Manager debe incluir el origen real del syslog.

---

## 5.6 `wazuh-logtest` indica `No decoder matched`

El syslog de Conpot fue predecodificado con un valor similar a:

```text
hostname: conpot[123]:
```

y no como:

```text
program_name: conpot
```

Por ello, los decoders basados en:

```xml
<program_name>^conpot</program_name>
```

no funcionaban en este laboratorio.

La solución validada utiliza `prematch` y `regex` sobre el contenido del mensaje.

---

## 5.7 `docker logs conpot-scada` no muestra información

Si el contenedor se ha iniciado con:

```text
--log-driver=syslog
```

`docker logs` puede no ser una fuente útil de diagnóstico.

Para depuración local:

1. detener el contenedor;
2. iniciarlo temporalmente sin el driver syslog;
3. observar `docker logs -f conpot-scada`;
4. una vez validado, volver a iniciar la configuración con syslog.

---

# 6. Wazuh FIM — Caso 4

## 6.1 Reinyectar un PCAP FTP no genera una alerta FIM

Es comportamiento esperado.

FIM detecta un cambio real en el sistema de archivos. `tcpreplay` solo reproduce tramas y no crea ningún fichero.

La prueba válida requiere un `PUT` FTP real que cree o modifique un fichero dentro del directorio vigilado:

```text
/srv/ftp/contenidos
```

Después puede comprobarse:

```bash
jq -c '
  select(
    .syscheck.path? and
    (.syscheck.path | startswith("/srv/ftp/contenidos"))
  )
  |
  {
    rule: .rule.id,
    event: .syscheck.event,
    mode: .syscheck.mode,
    path: .syscheck.path,
    sha256: .syscheck.sha256_after
  }
' /var/ossec/logs/alerts/alerts.json
```

En la prueba validada, la creación de un fichero produjo la regla nativa Wazuh `554` en modo `realtime`.

---

## 6.2 El PUT se realiza pero no aparece FIM

Comprobar en VM2:

1. el fichero existe realmente en `/srv/ftp/contenidos`;
2. `wazuh-agent` está activo;
3. la ruta está configurada en `<syscheck>`;
4. `realtime="yes"` está activo para ese directorio.

Comprobar el agente:

```bash
systemctl status wazuh-agent
```

---

# 7. SSH — Casos 5 y 7

## 7.1 Caso 5: un PCAP SSH no demuestra una autenticación correcta

El Caso 5 validado se basa en el plano de host.

Cadena correcta:

```text
login SSH real
→ sshd
→ Wazuh Agent
→ evento de autenticación aceptada
→ regla temporal 100030
```

Para validar el caso debe realizarse una autenticación SSH real contra VM2.

Comprobar:

```bash
grep '"id":"100030"' /var/ossec/logs/alerts/alerts.json | tail
```

---

## 7.2 La regla `100030` no salta

Comprobar:

1. que el login fue aceptado realmente por `sshd`;
2. que el evento procede del agente `vm2-billetaje`;
3. que el Manager está procesando el evento dentro de la ventana temporal configurada;
4. que la regla activa mantiene el encadenamiento previsto con la regla nativa de autenticación correcta.

No confundir el Caso 5 con `100071`, que pertenece al escenario de fuerza bruta SSH del Caso 7.

---

## 7.3 Caso 7: `100070` permanece a cero pero `100071` aumenta

Esto puede ser correcto.

`100071` es una regla hija que eleva la criticidad de los eventos clasificados previamente por `100070` cuando se cumple la condición temporal.

Si la condición temporal se cumple, Wazuh puede registrar como alerta final la regla hija:

```text
100071
```

sin generar una segunda alerta independiente `100070`.

Por tanto:

```text
100070 = 0
100071 aumenta
```

no implica que el mecanismo base no se haya evaluado.

Comprobar los campos Suricata dentro de la alerta `100071`:

```text
5500020
5500021
```

---

# 8. Diagnóstico general de Wazuh

## 8.1 El sensor genera el evento pero no aparece en `alerts.json`

Si está habilitado `logall_json`, comprobar:

```bash
/var/ossec/logs/archives/archives.json
```

Interpretación:

```text
Aparece en archives.json
→ el Manager recibe el evento; revisar decoders/reglas.

No aparece en archives.json
→ revisar origen, agente, ruta, permisos o logcollector.
```

---

## 8.2 El Dashboard no muestra una alerta que sí está en `alerts.json`

Antes de modificar reglas:

1. comprobar el rango temporal del Dashboard;
2. eliminar filtros antiguos;
3. buscar directamente por `rule.id`;
4. comprobar si el evento se ha indexado.

`alerts.json` es la evidencia primaria de que Wazuh Manager generó la alerta.

---

# 9. Comprobación rápida de PCAP sintéticos

Antes de buscar un error en las reglas, comprobar que el PCAP contiene realmente el tráfico esperado.

Ejemplos:

```powershell
docker exec -it tcpreplay-sender sh -lc "tcpdump -nn -r /pcaps/ssh_bruteforce_billetaje.pcap 'tcp port 22' | head -20"
```

```powershell
docker exec -it tcpreplay-sender sh -lc "tcpdump -nn -r /pcaps/escaneo_activos_servicios.pcap | head -50"
```

```powershell
docker exec -it tcpreplay-sender sh -lc "tcpdump -nn -A -r /pcaps/http_en_502.pcap 'tcp port 502' | head -40"
```

---

# 10. Árbol rápido de decisión

## Suricata / Zeek no detectan

```text
¿El PCAP genera alerta/notificación offline?
│
├─ NO
│  └─ Revisar PCAP, regla, HOME_NET, script o protocolo.
│
└─ SÍ
   │
   ├─ ¿El sensor ve los paquetes en eth0?
   │  ├─ NO → revisar red Docker, MAC y tcprewrite.
   │  └─ SÍ
   │     └─ revisar velocidad de replay y estado del sensor.
   │
   └─ probar 200 pps y, si es necesario, 50 pps.
```

## El sensor detecta pero Wazuh no

```text
¿El evento aparece en el log fuente?
│
├─ NO → problema en el sensor.
│
└─ SÍ
   │
   ├─ ¿Aparece en archives.json?
   │  ├─ NO → agente / logcollector / ruta / permisos / transporte.
   │  └─ SÍ → decoder o regla Wazuh.
   │
   └─ Si está en alerts.json pero no en Dashboard → revisar indexación/filtros.
```

---

# 11. Checklist antes de una reproducción

```text
[ ] Se utiliza Invoke-CasosPracticos.ps1 para lanzar los escenarios automatizados.
[ ] Docker Desktop está operativo.
[ ] Los contenedores necesarios están levantados.
[ ] suricata-live / zeek-live y tcpreplay-sender comparten la red esperada.
[ ] Las MAC de los sensores se han recalculado tras recrear contenedores.
[ ] Se usa la misma consola PowerShell donde se definieron las variables MAC.
[ ] Las reglas cargan sin errores.
[ ] Los logs se han vaciado con Clear-Content, no borrado mientras el proceso está activo.
[ ] El PCAP sintético corresponde al caso que se quiere ejecutar.
[ ] El replay se realiza a 200 pps salvo diagnóstico específico.
[ ] Se monitoriza primero el log local del sensor.
[ ] Después se comprueba alerts.json.
[ ] Solo al final se comprueba el Dashboard.
```

---

# 12. Principios que evitan diagnósticos incorrectos

- No interpretar cada alerta bruta como un incidente independiente.
- No atribuir a `tcpreplay` cambios de estado que requieren una sesión real.
- No cambiar reglas que ya funcionan antes de verificar PCAP, MAC, red y velocidad.
- No utilizar resultados offline como sustituto de la validación live; se usan como diagnóstico.
- No confundir el Caso 5 (`100030`, autenticación SSH real) con el Caso 7 (`100070/100071`, patrón de fuerza bruta de red).
- No asumir que un campo nulo en un comando `jq` implica pérdida de datos sin revisar primero la estructura JSON.
- Mantener separados los PCAP sintéticos del laboratorio y cualquier captura procedente del entorno real.

---

## Nota final

Esta guía documenta problemas observados durante el desarrollo del laboratorio y las soluciones que resultaron válidas en la configuración utilizada para el TFG. En otras versiones de las herramientas, sistemas anfitriones o topologías Docker pueden ser necesarios ajustes adicionales.
