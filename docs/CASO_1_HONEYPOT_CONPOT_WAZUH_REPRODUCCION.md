# Caso 1 — Honeypot Conpot + Wazuh por Syslog UDP 514

Guía de reproducción segura y repetible del **Caso 1 del TFG**: despliegue de un honeypot SCADA/Modbus con **Conpot en Docker Windows**, envío de logs por **syslog UDP 514** hacia **Wazuh Manager**, decodificación personalizada y generación de alertas locales.

> Objetivo del caso: detectar cualquier interacción Modbus contra el honeypot SCADA y generar alertas en Wazuh, aunque la petición Modbus devuelva `Invalid address`.

---

## 0. Arquitectura validada

### Componentes

| Componente | Ubicación | Función |
|---|---|---|
| Wazuh Manager | VM Ubuntu | Recibe syslog UDP 514, aplica decoders/reglas y genera alertas |
| Conpot | Docker Desktop en Windows | Honeypot SCADA/Modbus |
| Cliente Modbus | Windows PowerShell | Genera lecturas/escrituras contra Conpot |
| Dashboard Wazuh | Navegador | Visualización de alertas |

### Direccionamiento usado en la prueba

| Elemento | IP / Puerto |
|---|---|
| Wazuh Manager | `192.168.56.10` |
| Host Windows / Docker Desktop visto por Wazuh | `192.168.56.1` |
| Cliente visto por Conpot | `172.17.0.1` |
| Puerto syslog Wazuh | UDP `514` |
| Puerto Modbus expuesto en Windows | TCP `502` |
| Puerto Modbus interno de Conpot | TCP `5020` |
| Puerto HTTP expuesto opcional | TCP `8080` |
| Puerto HTTP interno de Conpot | TCP `8800` |

Punto importante:

```text
Wazuh recibe el syslog desde 192.168.56.1, no desde 172.17.0.1.
```

`172.17.0.1` es la IP que Conpot ve como origen de la conexión Modbus dentro de Docker, pero el paquete syslog hacia Wazuh llega desde el host/Docker Desktop.

---

## 1. Errores detectados durante la implementación

### 1.1 Contenedor existente pero parado

Síntoma:

```powershell
docker ps
```

no muestra `conpot-scada`, pero al crear el contenedor sale:

```text
Conflict. The container name "/conpot-scada" is already in use
```

Diagnóstico:

```powershell
docker ps -a --filter "name=conpot-scada"
```

Solución:

```powershell
docker rm -f conpot-scada
```

---

### 1.2 `Exit 127` / `conpot: not found`

Síntoma:

```text
Exited (127)
sh: conpot: not found
```

Causa:

Se estaba arrancando la imagen con:

```powershell
sh -lc "conpot -t /templates/modbus_custom.xml"
```

pero en esa imagen el binario `conpot` no está disponible directamente en el `PATH`.

Solución recomendada:

No lanzar Conpot manualmente. Usar el comando por defecto de la imagen:

```powershell
docker run -d --name conpot-scada `
  -p 502:5020 `
  -p 8080:8800 `
  honeynet/conpot:latest
```

Para el caso validado del TFG no hace falta plantilla custom.

---

### 1.3 Puerto interno incorrecto

No usar:

```powershell
-p 502:502
-p 80:80
```

Usar:

```powershell
-p 502:5020
-p 8080:8800
```

Porque Conpot suele escuchar internamente en:

```text
Modbus: 5020
HTTP: 8800
```

---

### 1.4 El XML custom no era una plantilla completa

El fragmento:

```xml
<slave id="1">
  <coils>
    <block name="a"><startAddress>0</startAddress><size>100</size></block>
  </coils>
  <holding_registers>
    <block name="b"><startAddress>0</startAddress><size>100</size></block>
  </holding_registers>
</slave>
```

no es una plantilla completa de Conpot. Es solo un fragmento Modbus.

Una plantilla completa suele tener estructura de carpeta:

```text
template.xml
modbus/
  modbus.xml
http/
  http.xml
snmp/
  snmp.xml
...
```

Para reproducir el caso 1 con seguridad, usar la plantilla default de la imagen.

---

### 1.5 `No decoder matched` en `wazuh-logtest`

El problema clave era que el syslog real llegaba así:

```text
Jun 25 20:45:04 conpot[123]: 2026-06-25 20:45:04,539 New Modbus connection from 172.17.0.1:52086. (...)
```

Wazuh lo predecodificaba como:

```text
hostname: 'conpot[123]:'
```

y **no** como:

```text
program_name: 'conpot'
```

Por eso no funcionaban decoders basados en:

```xml
<program_name>^conpot</program_name>
```

Solución: usar decoders sin `program_name`, basados en `prematch` y `regex`.

---

### 1.6 `Invalid address` no es fallo del caso

El comando:

```powershell
modbus -v -s 1 127.0.0.1:502 h@0
```

puede devolver:

```text
0: Invalid address
```

Eso no invalida la prueba. De hecho es útil, porque Conpot genera:

```text
Modbus Error: Exception code = 2
```

y permite validar una regla de error Modbus.

La alerta del caso 1 no depende de que la lectura sea correcta, sino de que haya interacción Modbus con el honeypot.

---

## 2. Configuración de Wazuh Manager

Todo esto se realiza en la VM Ubuntu donde está Wazuh Manager.

---

### 2.1 Habilitar recepción syslog UDP 514

Editar:

```bash
sudo micro /var/ossec/etc/ossec.conf
```

Añadir o comprobar este bloque:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>192.168.56.0/24</allowed-ips>
</remote>
```

Notas:

- En esta prueba, Docker Desktop envía el syslog desde `192.168.56.1`.
- Por tanto, `allowed-ips` debe incluir `192.168.56.1`.
- No basta con permitir `172.17.0.0/16`, porque esa IP es interna de Docker y no es el origen del syslog que ve Wazuh.

---

### 2.2 Activar archivado JSON

En el mismo fichero:

```bash
sudo micro /var/ossec/etc/ossec.conf
```

Comprobar que existe:

```xml
<global>
  <logall>yes</logall>
  <logall_json>yes</logall_json>
</global>
```

En esta implementación, activar:

```xml
<logall_json>yes</logall_json>
```

fue el punto que hizo que las alertas empezaran a aparecer correctamente tras haber validado decoders/reglas con `wazuh-logtest`.

Reiniciar Wazuh:

```bash
sudo systemctl restart wazuh-manager
```

Comprobar que escucha en UDP 514:

```bash
sudo ss -lunp | grep ':514'
```

---

## 3. Decoders de Conpot

Editar:

```bash
sudo micro /var/ossec/etc/decoders/local_decoder.xml
```

Añadir estos decoders:

```xml
<decoder name="conpot-modbus-connection">
  <prematch>New Modbus connection from</prematch>
  <regex>New Modbus connection from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+)</regex>
  <order>srcip,srcport</order>
</decoder>

<decoder name="conpot-modbus-session">
  <prematch>New modbus session from</prematch>
  <regex>New modbus session from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)</regex>
  <order>srcip</order>
</decoder>

<decoder name="conpot-modbus-traffic">
  <prematch>Modbus traffic from</prematch>
  <regex>Modbus traffic from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):</regex>
  <order>srcip</order>
</decoder>

<decoder name="conpot-modbus-error">
  <prematch>Modbus Error: Exception code</prematch>
  <regex>Modbus Error: Exception code = ([0-9]+)</regex>
  <order>extra_data</order>
</decoder>
```

Importante:

No usar esta estructura para este caso concreto:

```xml
<decoder name="conpot">
  <program_name>^conpot</program_name>
</decoder>
```

porque el syslog real se predecodifica como `hostname: conpot[123]:` y no expone `program_name: conpot`.

---

## 4. Reglas locales de Wazuh

Editar:

```bash
sudo micro /var/ossec/etc/rules/local_rules.xml
```

Añadir:

```xml
<group name="honeypot,scada,conpot,">
  <rule id="100010" level="12">
    <decoded_as>conpot-modbus-connection</decoded_as>
    <description>Interaccion con honeypot SCADA detectada desde $(srcip)</description>
    <group>honeypot,scada,ot_security,</group>
  </rule>

  <rule id="100011" level="10">
    <decoded_as>conpot-modbus-traffic</decoded_as>
    <description>Trafico Modbus registrado en honeypot SCADA desde $(srcip)</description>
    <group>honeypot,scada,modbus,ot_security,</group>
  </rule>

  <rule id="100012" level="8">
    <decoded_as>conpot-modbus-error</decoded_as>
    <description>Error Modbus generado por interaccion con honeypot SCADA. Codigo $(extra_data)</description>
    <group>honeypot,scada,modbus_error,ot_security,</group>
  </rule>
</group>
```

Reiniciar:

```bash
sudo systemctl restart wazuh-manager
```

Comprobar errores de carga:

```bash
sudo tail -n 100 /var/ossec/logs/ossec.log | grep -Ei "decoder|rule|100010|100011|100012|error|invalid"
```

Nota:

Si aparece:

```text
Too many fields for JSON decoder
```

probablemente viene de otro flujo activo, por ejemplo Suricata/eve.json, no de Conpot.

---

## 5. Arranque de Conpot desde cero

En Windows PowerShell:

```powershell
docker rm -f conpot-scada 2>$null

docker run -d --name conpot-scada `
  -p 502:5020 `
  -p 8080:8800 `
  --log-driver=syslog `
  --log-opt syslog-address=udp://192.168.56.10:514 `
  --log-opt tag=conpot `
  honeynet/conpot:latest
```

Comprobar que está en ejecución:

```powershell
docker ps
```

Debe aparecer:

```text
conpot-scada   Up
```

Si no aparece, comprobar:

```powershell
docker ps -a --filter "name=conpot-scada"
```

y logs:

```powershell
docker logs --tail 100 conpot-scada
```

Ojo: si se arrancó con `--log-driver=syslog`, puede que `docker logs` no muestre información útil. Para depurar Conpot sin syslog:

```powershell
docker rm -f conpot-scada 2>$null

docker run -d --name conpot-scada `
  -p 502:5020 `
  -p 8080:8800 `
  honeynet/conpot:latest

docker logs -f conpot-scada
```

Una vez validado, volver a lanzarlo con `--log-driver=syslog`.

---

## 6. Comandos Modbus para hacer saltar reglas

Todos los comandos se lanzan desde Windows PowerShell.

---

### 6.1 Regla 100010 — Conexión al honeypot

Comando:

```powershell
modbus -v -s 1 127.0.0.1:502 h@0
```

Log esperado en Conpot/Wazuh:

```text
New Modbus connection from 172.17.0.1:xxxxx
```

Decoder esperado:

```text
conpot-modbus-connection
```

Regla esperada:

```text
100010
```

---

### 6.2 Regla 100011 — Tráfico Modbus

El mismo comando también genera tráfico Modbus:

```powershell
modbus -v -s 1 127.0.0.1:502 h@0
```

Log esperado:

```text
Modbus traffic from 172.17.0.1: {'request': ..., 'slave_id': 1, 'function_code': 3, 'response': ...}
```

Decoder esperado:

```text
conpot-modbus-traffic
```

Regla esperada:

```text
100011
```

Comandos alternativos para generar tráfico adicional:

```powershell
modbus -v -s 1 127.0.0.1:502 c@0
```

```powershell
modbus -v -s 1 127.0.0.1:502 d@0
```

---

### 6.3 Regla 100012 — Error Modbus

Comando validado:

```powershell
modbus -v -s 1 127.0.0.1:502 h@0
```

Salida esperada del cliente:

```text
0: Invalid address
```

Log esperado en Conpot:

```text
Modbus Error: Exception code = 2
```

Decoder esperado:

```text
conpot-modbus-error
```

Regla esperada:

```text
100012
```

Prueba adicional de escritura:

```powershell
modbus -v -s 1 127.0.0.1:502 h@0=1234
```

Si el cliente `modbus` no acepta esa sintaxis, usar la lectura `h@0`, que ya provoca error en este entorno.

---

## 7. Validación con tcpdump

En Wazuh Manager:

```bash
sudo tcpdump -ni any udp port 514 -A
```

Desde Windows:

```powershell
modbus -v -s 1 127.0.0.1:502 h@0
```

Debe verse algo parecido a:

```text
192.168.56.1.xxxxx > 192.168.56.10.514: SYSLOG
Jun 25 20:45:04 conpot[123]: ... New Modbus connection from 172.17.0.1:52086
Jun 25 20:45:04 conpot[123]: ... Modbus traffic from 172.17.0.1: ...
Jun 25 20:45:04 conpot[123]: ... Modbus Error: Exception code = 2
```

Si `tcpdump` ve paquetes, la red y Docker syslog funcionan.

Si Wazuh no alerta pero `tcpdump` sí ve paquetes, revisar:

1. `allowed-ips`.
2. Decoders.
3. Reglas.
4. `logall_json`.
5. Filtro del dashboard.

---

## 8. Validación con wazuh-logtest

Ejecutar:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

---

### 8.1 Test de conexión

Pegar:

```text
Jun 25 20:45:04 conpot[123]: 2026-06-25 20:45:04,539 New Modbus connection from 172.17.0.1:52086. (3ddfd2d1-774a-4964-b631-6ebfbf620f64)
```

Resultado esperado:

```text
**Phase 2: Completed decoding.
        name: 'conpot-modbus-connection'
        srcip: '172.17.0.1'
        srcport: '52086'

**Phase 3: Completed filtering.
        id: '100010'
        level: '12'
```

---

### 8.2 Test de tráfico

Pegar:

```text
Jun 25 20:45:04 conpot[123]: 2026-06-25 20:45:04,540 Modbus traffic from 172.17.0.1: {'request': b'dbcb00000006010300000001', 'slave_id': 1, 'function_code': 3, 'response': b'8302'}
```

Resultado esperado:

```text
decoder.name: conpot-modbus-traffic
rule.id: 100011
```

---

### 8.3 Test de error

Pegar:

```text
Jun 25 20:45:04 conpot[123]: 2026-06-25 20:45:04,540 Exception caught: Modbus Error: Exception code = 2. (A proper response will be sent to the peer)
```

Resultado esperado:

```text
decoder.name: conpot-modbus-error
rule.id: 100012
```

---

## 9. Comprobación de alertas por consola

En Wazuh Manager:

```bash
sudo grep "100010" /var/ossec/logs/alerts/alerts.log | tail -20
```

```bash
sudo grep "100011" /var/ossec/logs/alerts/alerts.log | tail -20
```

```bash
sudo grep "100012" /var/ossec/logs/alerts/alerts.log | tail -20
```

Todas juntas:

```bash
sudo grep -E "100010|100011|100012|honeypot|conpot|Modbus" /var/ossec/logs/alerts/alerts.log | tail -50
```

En JSON:

```bash
sudo grep -E '"id":"100010"|"id":"100011"|"id":"100012"' /var/ossec/logs/alerts/alerts.json | tail -20
```

También puede revisarse el archivo de archivo si está activo `logall_json`:

```bash
sudo grep -i "conpot\|Modbus" /var/ossec/logs/archives/archives.json | tail -20
```

---

## 10. Validación en Wazuh Dashboard

En Wazuh Dashboard usar un rango temporal amplio:

```text
Last 24 hours
```

No filtrar por agente, porque los eventos entran por syslog directo al Wazuh Manager.

Búsquedas útiles:

```text
rule.id:100010
```

```text
rule.id:100011
```

```text
rule.id:100012
```

```text
rule.groups:honeypot
```

```text
decoder.name:conpot-modbus-connection
```

```text
decoder.name:conpot-modbus-traffic
```

```text
decoder.name:conpot-modbus-error
```

```text
"New Modbus connection"
```

```text
"Modbus traffic from"
```

```text
"Modbus Error"
```

---

## 11. Secuencia rápida de reproducción

Cuando el entorno ya está configurado, para repetir el caso desde cero:

### 11.1 En Wazuh Manager

```bash
sudo systemctl restart wazuh-manager
sudo ss -lunp | grep ':514'
sudo tail -f /var/ossec/logs/alerts/alerts.log
```

### 11.2 En Windows PowerShell

```powershell
docker rm -f conpot-scada 2>$null

docker run -d --name conpot-scada `
  -p 502:5020 `
  -p 8080:8800 `
  --log-driver=syslog `
  --log-opt syslog-address=udp://192.168.56.10:514 `
  --log-opt tag=conpot `
  honeynet/conpot:latest

modbus -v -s 1 127.0.0.1:502 h@0
```

### 11.3 En Dashboard

Buscar:

```text
rule.groups:honeypot
```

o:

```text
rule.id:100010
```

---

## 12. Checklist final

Antes de dar el caso por reproducido, comprobar:

- [ ] `docker ps` muestra `conpot-scada` como `Up`.
- [ ] Wazuh escucha en UDP 514.
- [ ] `tcpdump` en Wazuh ve los logs syslog desde `192.168.56.1`.
- [ ] `wazuh-logtest` matchea `conpot-modbus-connection`.
- [ ] `wazuh-logtest` dispara `rule.id:100010`.
- [ ] El comando `modbus -v -s 1 127.0.0.1:502 h@0` genera logs en Conpot.
- [ ] Aparece alerta `100010`.
- [ ] Aparece alerta `100011` si está configurada.
- [ ] Aparece alerta `100012` si está configurada.
- [ ] El dashboard muestra las alertas con rango `Last 24 hours`.
- [ ] No hay filtro por agente que oculte los eventos.
- [ ] Se guardan capturas para el TFG.

---

## 13. Capturas recomendadas para el TFG

Guardar capturas de:

1. `docker ps` mostrando `conpot-scada` levantado.
2. PowerShell con el comando Modbus y la respuesta `Invalid address`.
3. `tcpdump` mostrando syslog UDP 514 hacia Wazuh.
4. `wazuh-logtest` mostrando el decoder y la regla.
5. `alerts.log` con `rule.id:100010`.
6. Dashboard Wazuh con filtro `rule.groups:honeypot`.
7. Detalle de la alerta con:
   - `rule.id`
   - `rule.level`
   - `rule.description`
   - `srcip`
   - `decoder.name`
   - `rule.groups`

---

## 14. Resumen ejecutivo para memoria

El Caso 1 implementa un honeypot SCADA basado en Conpot, expuesto en el puerto Modbus/TCP 502 del host Windows. El contenedor Docker envía sus logs al Wazuh Manager mediante el driver syslog de Docker sobre UDP/514. Wazuh recibe los eventos, aplica decoders personalizados para identificar conexiones, tráfico y errores Modbus, y genera alertas locales de seguridad agrupadas como `honeypot`, `scada` y `ot_security`.

La prueba positiva consiste en ejecutar una lectura Modbus contra `127.0.0.1:502`. Aunque la petición devuelve `Invalid address`, Conpot registra la conexión y el tráfico, lo que permite demostrar la detección de interacción no autorizada con un activo SCADA simulado.

---

## 15. Comando mínimo definitivo

### Wazuh ya configurado

```bash
sudo systemctl restart wazuh-manager
sudo ss -lunp | grep ':514'
```

### Windows

```powershell
docker rm -f conpot-scada 2>$null

docker run -d --name conpot-scada `
  -p 502:5020 `
  -p 8080:8800 `
  --log-driver=syslog `
  --log-opt syslog-address=udp://192.168.56.10:514 `
  --log-opt tag=conpot `
  honeynet/conpot:latest

modbus -v -s 1 127.0.0.1:502 h@0
```

### Buscar alerta

```text
rule.groups:honeypot
```

o:

```text
rule.id:100010
```

---

Documento generado para guardar como guía interna de reproducción del Caso 1.
