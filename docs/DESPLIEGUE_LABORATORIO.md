# Despliegue del laboratorio

Esta guía describe cómo reconstruir el entorno utilizado en el TFG a partir de los ficheros incluidos en el repositorio.

> **Importante:** el repositorio no contiene credenciales, claves de agentes, certificados ni capturas procedentes de la infraestructura real. Algunas configuraciones se publican como fragmentos de referencia y deben integrarse en una instalación existente, no sustituir ficheros completos sin revisión.

---

## 1. Arquitectura del laboratorio

El entorno validado se divide en tres bloques:

```text
Host Windows
│
├─ Docker Desktop
│  ├─ suricata-live
│  ├─ tcpreplay-sender
│  ├─ zeek-live
│  └─ conpot-scada
│
├─ VM1 — 192.168.56.10
│  ├─ Wazuh Manager
│  ├─ Wazuh Indexer
│  └─ Wazuh Dashboard
│
└─ VM2 — 192.168.56.20
   ├─ Wazuh Agent
   ├─ vsftpd
   └─ OpenSSH
```

Versiones documentadas en el entorno original:

- Ubuntu VM1: 22.04.5 LTS.
- Wazuh Manager / Indexer / Dashboard: 4.14.1.
- Filebeat: 7.10.2.
- Zeek: 8.2.1.
- `tcpreplay-sender`: Alpine 3.20.
- Suricata: imagen `jasonish/suricata:latest`.
- Conpot: imagen `honeynet/conpot:latest`.

---

## 2. Estructura relevante del repositorio

```text
docker/
├─ docker-compose.yml
├─ .env.example
└─ README.md

vm/
├─ vm1-wazuh/
│  ├─ local_rules.xml
│  ├─ local_decoder.xml
│  ├─ ossec-relevant.xml
│  └─ versions-vm1.txt
│
└─ vm2-agent/
   ├─ ossec-relevant-vm2.txt
   ├─ vsftpd.conf
   ├─ sshd-relevant.conf
   └─ versions-vm2.txt

scripts/
└─ Invoke-CasosPracticos.ps1

docs/
├─ EJECUCION_RAPIDA.md
└─ TROUBLESHOOTING.md
```

Los nombres exactos pueden variar ligeramente si se reorganiza el repositorio.

---

## 3. Requisitos previos

Antes de reproducir el laboratorio se necesita:

- Windows con PowerShell.
- Docker Desktop.
- VirtualBox u otro hipervisor equivalente.
- Dos máquinas virtuales Ubuntu accesibles desde el host.
- Una instalación Wazuh all-in-one funcional en VM1.
- Wazuh Agent, vsftpd y OpenSSH instalados en VM2.
- Acceso de red entre el host y ambas máquinas virtuales.

Direccionamiento utilizado en el laboratorio original:

```text
VM1 Wazuh: 192.168.56.10
VM2 Agent: 192.168.56.20
```

Si se utilizan otras direcciones, deben adaptarse las configuraciones y el fichero `.env`.

---

## 4. Preparar VM1 — Wazuh

VM1 contiene Wazuh Manager, Indexer y Dashboard.

### 4.1 Copiar reglas y decoders

Los ficheros publicados en:

```text
vm/vm1-wazuh/local_rules.xml
vm/vm1-wazuh/local_decoder.xml
```

deben integrarse respectivamente en:

```text
/var/ossec/etc/rules/local_rules.xml
/var/ossec/etc/decoders/local_decoder.xml
```

Realizar copia de seguridad antes de sustituir cualquier fichero existente.

Ejemplo:

```bash
sudo cp /var/ossec/etc/rules/local_rules.xml \
  /var/ossec/etc/rules/local_rules.xml.bak

sudo cp /var/ossec/etc/decoders/local_decoder.xml \
  /var/ossec/etc/decoders/local_decoder.xml.bak
```

Después copiar las versiones del repositorio a sus rutas correspondientes.

### 4.2 Integrar la configuración relevante de `ossec.conf`

`ossec-relevant.xml` es un **fragmento de referencia**.

No debe copiarse encima de `/var/ossec/etc/ossec.conf`.

Debe comprobarse que la configuración activa contiene, como mínimo:

```xml
<global>
  <jsonout_output>yes</jsonout_output>
  <alerts_log>yes</alerts_log>
  <logall>yes</logall>
  <logall_json>yes</logall_json>
</global>
```

Canal seguro para agentes:

```xml
<remote>
  <connection>secure</connection>
  <port>1514</port>
  <protocol>tcp</protocol>
</remote>
```

Recepción syslog utilizada por Conpot:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>192.168.56.20/24</allowed-ips>
  <local_ip>192.168.56.10</local_ip>
</remote>
```

Adaptar las direcciones si la topología local es distinta.

### 4.3 Reiniciar y verificar

```bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
```

Comprobar recepción syslog:

```bash
sudo ss -lunp | grep ':514'
```

---

## 5. Preparar VM2 — Wazuh Agent, FTP y SSH

VM2 representa el endpoint utilizado por los casos de FIM y acceso SSH.

### 5.1 Wazuh Agent

El fichero:

```text
vm/vm2-agent/ossec-relevant-vm2.txt
```

documenta las secciones relevantes observadas en la configuración real.

Debe integrarse en una instalación funcional de Wazuh Agent.

No contiene ni sustituye:

```text
/var/ossec/etc/client.keys
```

La asociación del agente con el Manager debe realizarse de forma independiente y segura.

Para el Caso 4, la configuración FIM utilizada fue:

```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>300</frequency>
  <directories check_all="yes" realtime="yes" report_changes="yes">/srv/ftp/contenidos</directories>
  <directories check_all="yes">/etc/vsftpd.conf</directories>
  <alert_new_files>yes</alert_new_files>
  <auto_ignore>no</auto_ignore>
</syscheck>
```

Crear el directorio si no existe:

```bash
sudo mkdir -p /srv/ftp/contenidos
```

### 5.2 vsftpd

El fichero:

```text
vm/vm2-agent/vsftpd.conf
```

corresponde a la configuración utilizada durante la validación.

Antes de sustituir una configuración existente:

```bash
sudo cp /etc/vsftpd.conf /etc/vsftpd.conf.bak
```

Después aplicar la configuración del repositorio y reiniciar:

```bash
sudo systemctl restart vsftpd
sudo systemctl status vsftpd
```

### 5.3 OpenSSH

`sshd-relevant.conf` documenta únicamente parámetros efectivos relevantes del servicio SSH.

No es un `sshd_config` completo y no debe utilizarse para sobrescribir `/etc/ssh/sshd_config`.

Comprobar la configuración efectiva:

```bash
sudo sshd -T
```

Reiniciar SSH solo después de validar la sintaxis:

```bash
sudo sshd -t
sudo systemctl restart ssh
```

### 5.4 Reiniciar Wazuh Agent

```bash
sudo systemctl restart wazuh-agent
sudo systemctl status wazuh-agent
```

---

## 6. Desplegar los contenedores Docker

### 6.1 Crear el fichero local `.env`

Desde la raíz del repositorio:

```powershell
Copy-Item docker\.env.example docker\.env
```

Editar `docker\.env` si las rutas o la IP del Manager son diferentes.

El entorno original utilizó:

```text
WAZUH_MANAGER_IP=192.168.56.10
```

El fichero `.env` no debe subirse a Git.

### 6.2 Validar el Compose

```powershell
docker compose `
  --env-file docker\.env `
  -f docker\docker-compose.yml `
  config
```

### 6.3 Levantar el laboratorio

```powershell
docker compose `
  --env-file docker\.env `
  -f docker\docker-compose.yml `
  up -d
```

### 6.4 Comprobar servicios

```powershell
docker compose `
  --env-file docker\.env `
  -f docker\docker-compose.yml `
  ps
```

Deben aparecer:

```text
suricata-live
tcpreplay-sender
zeek-live
conpot-scada
```

---

## 7. Red Docker

La red de sensores utilizada es:

```text
Nombre:  suricata-lab
Driver:  bridge
Subnet:  172.20.0.0/16
Gateway: 172.20.0.1
```

Pertenecen a ella:

```text
suricata-live
tcpreplay-sender
zeek-live
```

Conpot utiliza deliberadamente el `bridge` predeterminado de Docker, reproduciendo la configuración validada.

Comprobar:

```powershell
docker network inspect suricata-lab
```

---

## 8. Rutas y PCAP

El laboratorio original utilizó rutas bajo:

```text
C:\tfg
```

Para utilizar directamente un clon del repositorio pueden adaptarse las variables del `.env`.

Ejemplo:

```text
PCAP_HOST_DIR=C:/tfg-github/pcaps-synthetic
SURICATA_RULES_DIR=C:/tfg-github/suricata/rules
SURICATA_CONFIG_FILE=C:/tfg-github/suricata/config/suricata.yaml
ZEEK_SCRIPT_DIR=C:/tfg-github/zeek/scripts
```

Los PCAP incluidos en el repositorio son sintéticos y fueron generados específicamente para las pruebas de laboratorio.

Las capturas procedentes del entorno real no se publican.

---

## 9. Ejecutar los casos prácticos

Una vez levantada la infraestructura:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

y:

```powershell
.\scripts\Invoke-CasosPracticos.ps1
```

Consultar también:

```text
docs/EJECUCION_RAPIDA.md
docs/TROUBLESHOOTING.md
```

---

## 10. Consideraciones sobre Zeek

El Caso 2 puede recrear `zeek-live` durante la ejecución para limpiar el estado previo del sensor y evitar que mecanismos internos de supresión de notificaciones afecten a la prueba.

Por este motivo, el identificador del contenedor y su dirección MAC pueden cambiar.

Los scripts de reproducción recalculan las MAC necesarias antes de utilizar `tcprewrite`.

---

## 11. Consideraciones sobre Conpot

La configuración validada de Conpot:

- utiliza `honeynet/conpot:latest`;
- usa la plantilla predeterminada incluida en la imagen;
- publica `502:5020`;
- publica `8080:8800`;
- envía logs mediante syslog UDP/514 a VM1.

Los XML almacenados en la carpeta `conpot/` son material auxiliar utilizado durante el desarrollo y no constituyen necesariamente la configuración efectiva del contenedor final.

---

## 12. Datos que no se incluyen

Por seguridad y confidencialidad, el repositorio no contiene:

- `client.keys` de Wazuh;
- contraseñas;
- tokens;
- claves privadas SSH;
- certificados privados;
- ficheros `.env` reales;
- logs operacionales completos;
- `alerts.json` o `archives.json` completos;
- capturas PCAP procedentes de la infraestructura tranviaria real;
- documentación interna de la instalación.

Cada usuario debe generar sus propias credenciales y registrar sus agentes Wazuh.

---

## 13. Verificación mínima

Antes de ejecutar los casos:

```text
[ ] VM1 responde en la IP configurada.
[ ] Wazuh Manager está activo.
[ ] Wazuh Dashboard es accesible.
[ ] VM2 tiene el Wazuh Agent activo.
[ ] VM2 aparece como agente conectado en Wazuh.
[ ] vsftpd está activo en VM2.
[ ] OpenSSH está activo en VM2.
[ ] /srv/ftp/contenidos está monitorizado por FIM.
[ ] Docker Desktop está iniciado.
[ ] Los cuatro contenedores están activos.
[ ] suricata-live, zeek-live y tcpreplay-sender pertenecen a suricata-lab.
[ ] Los PCAP sintéticos están disponibles en /pcaps.
```

---

## 14. Alcance de reproducibilidad

El repositorio permite reproducir la lógica experimental del TFG, las reglas de detección, los scripts y la topología del laboratorio.

No pretende ser una imagen completa o automatizada de una infraestructura de producción. La instalación base de Wazuh, el registro seguro de agentes, la creación de las máquinas virtuales y la adaptación del direccionamiento siguen siendo responsabilidad de quien despliega el entorno.
