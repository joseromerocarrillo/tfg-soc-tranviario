# Guía interna de reproducción (live) — Casos 1 a 5 + correspondencia global

> Documento complementario de `GUIA_REPRODUCCION_SURICATA_TFG_ACTUALIZADA.md`.
> Aquel cubre los casos que se detectan con **Suricata** (5b, 6, 7). Este cubre los
> casos **1, 2, 3, 4 y 5** bajo el mismo principio: el ataque se introduce como
> **tráfico anómalo en la red** y un analizador (**Zeek**, **Suricata** o un
> **cliente/script** de ataque) lo detecta y lo reporta a **Wazuh**.

---

## 1. Principio metodológico y limitaciones honestas

El proyecto usa dos familias de detectores. La técnica de inyección NO es la misma
para ambas, y esto debe quedar explícito ante el tribunal.

### 1.1 Analizadores pasivos de red — Suricata y Zeek

Inspeccionan las tramas que circulan por la interfaz. **No necesitan ser el extremo
real de la conexión**: ven la trama reinyectada con `tcpreplay`, la parsean y disparan.

- `tcpreplay` funciona perfectamente.
- Aplica a: **Caso 2 (Zeek/Modbus)**, **Caso 3 (Suricata/mov. lateral)** y a los ya
  documentados 5b, 6 y 7.
- Requiere el mismo truco de la guía Suricata: **reescribir la MAC destino** a la del
  contenedor sensor (Zeek o Suricata), porque el bridge Docker solo entrega al sensor
  las tramas dirigidas a su MAC.

### 1.2 Extremos interactivos y agentes de host — Conpot, Wazuh FIM, `auth.log`

Necesitan **una interacción real o un cambio de estado real** en una máquina.

Limitación técnica que debe conocerse y, si procede, escribirse en la memoria:

- **`tcpreplay` reinyecta tramas L2 en un sentido; NO levanta una sesión TCP real.**
  Al reinyectar hacia Conpot, su kernel responde el SYN con su propio ISN, que no casa
  con la secuencia del PCAP → el handshake no se completa → **Conpot no procesa el PDU
  Modbus y no registra interacción útil**. Por tanto `tcpreplay` por sí solo **no**
  dispara el honeypot.
- **FIM (syscheck)** alerta sobre cambios de ficheros en disco. Reinyectar un PUT FTP
  **no escribe ningún fichero** (no hay sesión real) → el hash no cambia → no hay alerta.
  **No se puede disparar FIM con tráfico inyectado**, por diseño.

### 1.3 Matriz de decisión

| Caso | Mecanismo original | ¿Inyección con `tcpreplay`? | Vía adoptada en esta guía |
|---|---|:--:|---|
| 1 — Honeypot Conpot | Honeypot (host) | No | **Cliente Modbus real** (recomendada) **o** regla señuelo en Suricata |
| 2 — Modbus/Zeek | Analizador pasivo | Sí | **Zeek live + tcpreplay** |
| 3 — Mov. lateral | Analizador pasivo (Suricata) | Sí | **Suricata live + tcpreplay** |
| 4 — FIM | FIM (host) | No | **PUT FTP real + FIM** (recomendada) **o** Zeek detecta `STOR` anónimo |
| 5 — Fuera de horario | Wazuh `auth.log` (host) | Parcial | **Suricata ve SSH + regla temporal Wazuh** (plano red) |

> Nota de defensa ante el tribunal: que dos casos (1 y 4) tengan también una variante de
> host **no es una debilidad**, es el argumento de defensa en profundidad. Lo que no se
> puede afirmar es que un honeypot o un FIM se validen "inyectando tráfico con tcpreplay":
> eso sería técnicamente incorrecto.

---

## 2. Infraestructura común

Se reutiliza la red `suricata-lab` y el contenedor `tcpreplay-sender` de la guía Suricata.
Se añaden, según el caso, un contenedor **Zeek** y un contenedor **atacante**.

Rutas sugeridas en Windows (paralelas a las de Suricata):

```text
C:\tfg\zeek\scripts\        # modbus_whitelist.zeek, modbus_acl.zeek, ftp_anon_notice.zeek
C:\tfg\zeek\logs\           # notice.log, modbus.log, ftp.log (en JSON)
C:\tfg\pcaps\               # PCAPs de ataque (compartido con tcpreplay-sender)
```

PCAPs nuevos referenciados en esta guía:

```text
modbus_no_autorizado.pcap     # Caso 2: peer/lectura/escritura Modbus fuera de ACL
movimiento_lateral.pcap       # Caso 3: SYN ofimática->SCADA + connect a 502
ftp_put_anonimo.pcap          # Caso 4 (vía B): USER anonymous + STOR sobre 21
ssh_fuera_horario.pcap        # Caso 5: conexión SSH hacia el servidor de billetaje
```

---

## 3. Caso 2 — Control de acceso Modbus con Zeek (live)

Zeek es **pasivo**: ve la trama Modbus reinyectada y aplica la lógica de ACL. Conversión
limpia desde el modo offline (`zeek -r`) al modo live (`zeek -i eth0`).

### 3.1 Arrancar Zeek en modo live

```powershell
docker rm -f zeek-live 2>$null

docker run -d --name zeek-live `
  --network suricata-lab `
  --cap-add=NET_ADMIN `
  --cap-add=NET_RAW `
  -v C:\tfg\zeek\scripts:/opt/zeek/share/zeek/site/tfg `
  -v C:\tfg\zeek\logs:/logs `
  zeek/zeek:latest `
  sh -lc "cd /logs && zeek -C -i eth0 redef::LogAscii::use_json=T /opt/zeek/share/zeek/site/tfg/modbus_whitelist.zeek"
```

Notas:

- `-C` ignora errores de checksum (las tramas reinyectadas y reescritas con `--fixcsum`
  pueden traer checksums que conviene no validar).
- `redef LogAscii::use_json=T` fuerza salida JSON, que Wazuh consume mejor.
- El analizador Modbus de Zeek está integrado; `modbus_whitelist.zeek` solo debe cargar
  `@load base/protocols/modbus` y tu lógica de ACL (diccionario `modbus_acl.zeek`).

### 3.2 Obtener la MAC del sensor Zeek

```powershell
$ZEEKMAC = (docker exec zeek-live sh -lc "cat /sys/class/net/eth0/address").Trim()
$SENDERMAC = (docker exec tcpreplay-sender sh -lc "cat /sys/class/net/eth0/address").Trim()
echo "ZEEKMAC=$ZEEKMAC"
echo "SENDERMAC=$SENDERMAC"
```

### 3.3 Abrir monitorización

```powershell
Get-Content C:\tfg\zeek\logs\notice.log -Wait | Select-String "Unauthorized"
```

(o `modbus.log` / el log propio que generen tus scripts).

### 3.4 Reinyectar el ataque Modbus

```powershell
docker exec -it tcpreplay-sender sh -lc "apk add --no-cache tcpreplay >/dev/null 2>&1 || true && tcprewrite --enet-dmac=$ZEEKMAC --enet-smac=$SENDERMAC --fixcsum --infile=/pcaps/modbus_no_autorizado.pcap --outfile=/tmp/replay.pcap && tcpreplay --intf1=eth0 --pps=200 /tmp/replay.pcap"
```

### 3.5 Alertas esperadas

```text
Zeek notice: UnauthorizedModbusPeer / UnauthorizedRead / UnauthorizedWrite
Wazuh:       reglas 100020 / 100021
```

### 3.6 Verificación en Wazuh (agente que monitoriza el log de Zeek)

Bloque esperado en `ossec.conf` del agente:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/media/sf_zeek_logs/notice.log</location>
</localfile>
```

```bash
tail -f /var/ossec/logs/alerts/alerts.json | jq -c 'select((.rule.id|tostring)|test("10002")) | {id:.rule.id, desc:.rule.description, src:.data.id_orig_h, dst:.data.id_resp_h}'
```

### 3.7 Diagnóstico offline (si live no genera notice)

```powershell
docker run --rm `
  -v C:\tfg\zeek\scripts:/opt/zeek/share/zeek/site/tfg `
  -v C:\tfg\pcaps:/pcaps `
  -v C:\tfg\zeek\logs\offline:/logs `
  zeek/zeek:latest `
  sh -lc "cd /logs && zeek -C -r /pcaps/modbus_no_autorizado.pcap /opt/zeek/share/zeek/site/tfg/modbus_whitelist.zeek"
```

Interpretación idéntica a la guía Suricata: si offline genera notice y live no, el problema
está en la entrega de tramas (MAC, red, `--pps`), no en el script ni en el PCAP.

---

## 4. Caso 3 — Movimiento lateral con Suricata (live)

Encaja **exactamente** en la guía Suricata existente; solo cambian PCAP y SIDs.

### 4.1 Contenido del PCAP

```text
Escaneo de servicios: SYN 192.168.21.24 -> 192.168.2.101, puertos 445, 1433, 502
Conexión completa:    handshake TCP completo 192.168.21.24 -> 192.168.2.101:502
```

### 4.2 Reinyección

```powershell
docker exec -it tcpreplay-sender sh -lc "tcprewrite --enet-dmac=$SURIMAC --enet-smac=$SENDERMAC --fixcsum --infile=/pcaps/movimiento_lateral.pcap --outfile=/tmp/replay.pcap && tcpreplay --intf1=eth0 --pps=200 /tmp/replay.pcap"
```

### 4.3 Alertas esperadas

```text
9000002 / 9000003 / 9000004  (escaneo de servicios y conexión a Modbus desde ofimática)
Wazuh: familia correspondiente del Caso 3
```

### 4.4 Comprobación

```powershell
Get-Content C:\tfg\suricata\logs\eve.json -Tail 200 | Select-String '9000002|9000003|9000004'
```

> Si ya lo tenías integrado en la guía Suricata, basta con añadir esta fila a la tabla
> resumen de la sección 12 de aquel documento y a la lista de PCAPs de la sección 2.

---

## 5. Caso 1 — Honeypot industrial Conpot

`tcpreplay` no puede impulsar Conpot (ver §1.2). Dos vías válidas; elige según qué quieras
demostrar.

### 5.1 Vía A (recomendada) — inyección con cliente Modbus real

Se inyecta **tráfico anómalo real** hacia el señuelo: una sesión Modbus genuina. Conpot la
registra y la reporta a Wazuh por syslog. Es lo único que demuestra de verdad el valor del
honeypot.

Contenedor atacante con `pymodbus`:

```powershell
$CONPOT_IP = (docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" conpot).Trim()
echo "CONPOT_IP=$CONPOT_IP"

docker run --rm --network suricata-lab python:3.12-alpine sh -lc "pip install -q pymodbus==3.* && python - <<'PY'
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('$CONPOT_IP', port=502)
c.connect()
c.read_holding_registers(0, count=8, slave=1)   # lectura de reconocimiento
c.write_register(1, 0x1337, slave=1)             # escritura no autorizada
c.close()
PY"
```

Detección esperada:

```text
Conpot registra la interacción Modbus (FC de lectura/escritura, IP origen, timestamp)
-> reenvío por syslog -> alerta Wazuh del Caso 1
```

Verificación:

```bash
tail -f /var/ossec/logs/alerts/alerts.json | jq -c 'select(.rule.groups|index("conpot")) | {id:.rule.id, desc:.rule.description, src:.data.srcip}'
```

> Honesto para el tribunal: aquí el "inyector" es un cliente Modbus, no `tcpreplay`. Sigue
> cumpliendo "introducir tráfico anómalo en la red", que es el espíritu de tu requisito.

### 5.2 Vía B (tcpreplay puro) — Conpot como señuelo + Suricata como detector

Si exiges `tcpreplay`, traslada la detección a Suricata con una premisa simple: **nadie
debe hablar con el señuelo**, luego cualquier tráfico hacia su IP es sospechoso.

Regla Suricata (una sola línea):

```suricata
alert ip any any -> [CONPOT_IP] any (msg:"OT-HONEYPOT interaccion con senuelo SCADA"; classtype:trojan-activity; sid:5500030; rev:1;)
```

Reinyección:

```powershell
docker exec -it tcpreplay-sender sh -lc "tcprewrite --enet-dmac=$SURIMAC --enet-smac=$SENDERMAC --fixcsum --infile=/pcaps/modbus_no_autorizado.pcap --outfile=/tmp/replay.pcap && tcpreplay --intf1=eth0 --pps=200 /tmp/replay.pcap"
```

> Coste conceptual: con la vía B, Conpot deja de ser el detector y pasa a ser decorado. Si
> la usas, dilo claramente en la memoria para no atribuir a Conpot una detección que en
> realidad hace Suricata.

---

## 6. Caso 4 — File Integrity Monitoring (SAE/SIV)

`tcpreplay` no puede cambiar un fichero en disco (ver §1.2). Dos vías.

### 6.1 Vía A (recomendada) — PUT FTP anónimo real + FIM

Se inyecta tráfico anómalo real (sesión FTP anónima con subida) que además cambia el
fichero en disco; FIM lo detecta. Mantiene intacta la garantía de integridad.

```powershell
$FTP_IP = (docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" ftp-saesiv).Trim()

docker run --rm --network suricata-lab alpine:3.20 sh -lc "apk add --no-cache curl >/dev/null 2>&1 && echo 'contenido manipulado' > /tmp/aviso.txt && curl -s -T /tmp/aviso.txt ftp://$FTP_IP/ --user anonymous: "
```

Detección esperada:

```text
syscheck (real-time inotify) detecta el fichero nuevo/modificado
-> alerta FIM Wazuh con path, hash SHA-256, timestamp y, si report_changes, el diff
```

Verificación:

```bash
tail -f /var/ossec/logs/alerts/alerts.json | jq -c 'select(.syscheck) | {id:.rule.id, path:.syscheck.path, event:.syscheck.event, sha:.syscheck.sha256_after}'
```

### 6.2 Vía B (tcpreplay puro) — Zeek detecta el `STOR` anónimo

Zeek parsea los comandos del canal de control FTP (puerto 21) sobre tráfico reinyectado.
Detectas **el comando**, no el cambio de integridad.

Script `ftp_anon_notice.zeek` (idea):

```zeek
@load base/protocols/ftp
event ftp_request(c: connection, command: string, arg: string) {
    if ( command == "STOR" && c$ftp$user == "anonymous" )
        NOTICE([$note=FTP::Anon_Upload, $conn=c, $msg=fmt("STOR anonimo: %s", arg)]);
}
```

Reinyección (hacia el sensor Zeek):

```powershell
docker exec -it tcpreplay-sender sh -lc "tcprewrite --enet-dmac=$ZEEKMAC --enet-smac=$SENDERMAC --fixcsum --infile=/pcaps/ftp_put_anonimo.pcap --outfile=/tmp/replay.pcap && tcpreplay --intf1=eth0 --pps=200 /tmp/replay.pcap"
```

> Coste conceptual: la vía B ya **no es FIM**. Demuestras detección de una subida anónima en
> el plano de red, no la integridad del fichero. Pierdes la propiedad más valiosa del FIM
> (detectar el cambio venga por donde venga). Decide cuál de las dos historias quieres contar.

---

## 7. Caso 5 — Acceso administrativo fuera de horario (plano de red)

Versión de red coherente con tu metodología: Suricata observa la **conexión** SSH y Wazuh
la **eleva por horario**. Es el mismo mecanismo que la "elevación por horario" del Caso 7.

### 7.1 Reinyección de la conexión SSH

```powershell
docker exec -it tcpreplay-sender sh -lc "tcprewrite --enet-dmac=$SURIMAC --enet-smac=$SENDERMAC --fixcsum --infile=/pcaps/ssh_fuera_horario.pcap --outfile=/tmp/replay.pcap && tcpreplay --intf1=eth0 --pps=200 /tmp/replay.pcap"
```

### 7.2 Detección y elevación

```text
Suricata: evento de conexion SSH hacia el servidor de billetaje
Wazuh 100071: eleva la criticidad si la hora del Manager esta fuera de 07:00-20:00
```

Misma observación que en la guía Suricata: la regla `100071` evalúa la **hora real del
Manager**, no la del PCAP. Para demo diurna, amplía temporalmente el `<time>` de `100071`,
reinyecta, verifica y revierte.

### 7.3 Limitación que debe constar

```text
El plano de red ve el INTENTO/acceso (conexion SSH), no el EXITO/FRACASO de autenticacion,
porque la sesion SSH viaja cifrada. La "verdad de campo" (exito real) solo la da el
auth.log via agente Wazuh (reglas 5715 -> 100030). Ambos planos son complementarios.
```

---

## 8. Tabla de correspondencia global (caso → inyección → detección → Wazuh)

> Esta es la tabla que tenías pendiente como anexo del TFG.

| Caso | Inyector | PCAP / acción | Detector | Log fuente | SID/Notice | Regla Wazuh |
|---|---|---|---|---|---|---|
| 1 — Honeypot | Cliente Modbus (A) / tcpreplay (B) | sesión Modbus / `modbus_no_autorizado.pcap` | Conpot (A) / Suricata (B) | log Conpot / `eve.json` | — / `5500030` | grupo `conpot` / familia señuelo |
| 2 — Modbus ACL | tcpreplay | `modbus_no_autorizado.pcap` | Zeek live | `notice.log` | `UnauthorizedPeer/Read/Write` | `100020` / `100021` |
| 3 — Mov. lateral | tcpreplay | `movimiento_lateral.pcap` | Suricata live | `eve.json` | `9000002/3/4` | familia Caso 3 |
| 4 — FIM | Cliente FTP (A) / tcpreplay (B) | PUT anónimo / `ftp_put_anonimo.pcap` | Wazuh syscheck (A) / Zeek (B) | `syscheck` / `ftp.log` | — / `FTP::Anon_Upload` | regla FIM / regla notice FTP |
| 5 — Fuera horario | tcpreplay | `ssh_fuera_horario.pcap` | Suricata + Wazuh temporal | `eve.json` | evento SSH | `100071` (eleva por horario) |
| 5b — DPI puerto/protocolo | tcpreplay | `http_en_502` / `ssh_en_8080` / `binario_..._3389` | Suricata live | `eve.json` | `5500001/07/08` | familia `10005x` |
| 6 — Escaneo | tcpreplay | `escaneo_activos_servicios.pcap` | Suricata live | `eve.json` | `5500010/11` | `100060` |
| 7 — Fuerza bruta SSH | tcpreplay | `ssh_bruteforce_billetaje.pcap` | Suricata live | `eve.json` | `5500020/21` | `100070` / `100071` |

---

## 9. Checklist por familia

**Casos pasivos (2, 3 — y 5b/6/7):**

```text
[ ] Sensor (zeek-live / suricata-live) recreado tras cambios de config.
[ ] Logs limpiados (Clear-Content / cd /logs && : > notice.log).
[ ] Sensor y tcpreplay-sender en la red suricata-lab.
[ ] MAC del sensor recalculada (ZEEKMAC / SURIMAC) tras recrear contenedores.
[ ] Misma terminal PowerShell donde se definieron las MACs.
[ ] --pps=200 (bajar a 50 si no saltan alertas en live).
[ ] Monitorizacion abierta antes de reinyectar.
[ ] Verificado SID/Notice en log de Suricata/Zeek.
[ ] Verificada alerta en Wazuh Manager.
```

**Casos de host (1-A, 4-A, 5 plano host):**

```text
[ ] El detector de host esta activo (Conpot escuchando / syscheck en real-time / agente leyendo auth.log).
[ ] El inyector hace una interaccion REAL (cliente Modbus / FTP / SSH), no tcpreplay.
[ ] Verificado el log local del detector antes de mirar Wazuh.
[ ] Verificada la alerta correlada en Wazuh Manager.
```

---

## 10. Pendientes y decisiones a cerrar

1. **Casos 1 y 4: decidir vía A o B** y reflejarlo en la memoria con honestidad sobre qué
   plano detecta cada uno. No mezclar (no atribuir a Conpot/FIM una detección de red).
2. Generar/validar los PCAPs nuevos: `modbus_no_autorizado.pcap`, `movimiento_lateral.pcap`,
   `ftp_put_anonimo.pcap`, `ssh_fuera_horario.pcap`.
3. Confirmar rutas de logs de Zeek compartidas con la VM del agente Wazuh (equivalente a
   `/media/sf_logs` de Suricata).
4. Limpieza menor en la guía Suricata: retirar `5500006` del resumen de SIDs (§3.2), ya que
   se descartó por no demostrable.
5. Unificar IDs de reglas Wazuh: en la guía Suricata conviven "familia `10005x`" y los IDs
   concretos `100060/100070/100071`. Fijar un esquema único de numeración.
