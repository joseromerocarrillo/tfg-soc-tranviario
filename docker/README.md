# Despliegue Docker del laboratorio

Este directorio contiene la definición Docker Compose equivalente al despliegue que se utilizó durante la validación experimental del TFG.

La definición se ha reconstruido a partir de la configuración efectiva de los contenedores Docker activos, no a partir de una arquitectura teórica.

## Componentes

| Servicio | Imagen | Red |
|---|---|---|
| `suricata-live` | `jasonish/suricata:latest` | `suricata-lab` |
| `tcpreplay-sender` | `alpine:3.20` | `suricata-lab` |
| `zeek-live` | `zeek/zeek:8.2.1` | `suricata-lab` |
| `conpot-scada` | `honeynet/conpot:latest` | `bridge` |

Wazuh no se ejecuta dentro de este Compose.

La arquitectura validada mantiene:

- Wazuh Manager, Indexer y Dashboard en la VM1 (`192.168.56.10`).
- Wazuh Agent, vsftpd y OpenSSH en la VM2 (`192.168.56.20`).
- Los sensores y herramientas auxiliares indicados arriba en Docker Desktop sobre Windows.

## Red Docker

La red utilizada por Suricata, Zeek y tcpreplay es:

```text
Nombre:  suricata-lab
Driver:  bridge
Subnet:  172.20.0.0/16
Gateway: 172.20.0.1
```

Las direcciones IP y MAC concretas de los contenedores no se fijan en el Compose porque son valores efímeros.

El script `Invoke-CasosPracticos.ps1` obtiene las MAC actuales después de crear o recrear los sensores antes de ejecutar `tcprewrite`.

## Configuración equivalente al laboratorio original

Por defecto, el Compose utiliza las mismas rutas que el laboratorio validado:

```text
C:\tfg\suricata\rules
C:\tfg\suricata\config\suricata.yaml
C:\tfg\suricata\logs
C:\tfg\pcaps
C:\tfg\zeek\scripts
C:\tfg\zeek\logs
```

Estas rutas pueden modificarse mediante `docker/.env`.

## Variables de entorno

Crear el fichero local:

```powershell
Copy-Item docker\.env.example docker\.env
```

El fichero `.env` permite configurar:

- IP del Wazuh Manager.
- Directorio de reglas Suricata.
- fichero `suricata.yaml`.
- directorio de logs Suricata.
- directorio de PCAP sintéticos.
- scripts Zeek.
- logs Zeek.

`docker/.env` no debe versionarse.

## Validar el Compose sin modificar el laboratorio

Desde la raíz del repositorio:

```powershell
docker compose --env-file docker\.env.example -f docker\docker-compose.yml config
```

Este comando solo valida y expande la configuración.

## Primera migración desde los contenedores creados con `docker run`

Los contenedores originales tienen los mismos nombres que los definidos en Compose.

Por ello, no ejecutar directamente `docker compose up -d` mientras existan los contenedores antiguos.

Comprobar primero:

```powershell
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"
```

Cuando se quiera realizar la migración controlada, eliminar únicamente los cuatro contenedores del laboratorio:

```powershell
docker rm -f suricata-live tcpreplay-sender zeek-live conpot-scada
```

Los ficheros de configuración, reglas, PCAP y logs almacenados en el host no se eliminan con este comando.

Después:

```powershell
docker compose --env-file docker\.env -f docker\docker-compose.yml up -d
```

Comprobar:

```powershell
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
```

## Estado esperado

Deben aparecer:

```text
suricata-live
tcpreplay-sender
zeek-live
conpot-scada
```

Conpot debe publicar:

```text
502  -> 5020/tcp
8080 -> 8800/tcp
```

## Comprobación de la red

```powershell
docker network inspect suricata-lab
```

Deben pertenecer a ella:

```text
suricata-live
tcpreplay-sender
zeek-live
```

`conpot-scada` debe permanecer en el `bridge` por defecto, reproduciendo el despliegue original.

## Ejecución de los casos

Una vez levantada la infraestructura:

```powershell
.\scripts\Invoke-CasosPracticos.ps1
```

El script:

- comprueba el estado de Docker;
- inicia contenedores existentes que estén parados;
- puede utilizar Docker Compose si falta alguno;
- recalcula las MAC necesarias para `tcprewrite`;
- recrea `zeek-live` específicamente al ejecutar el Caso 2;
- lanza los estímulos correspondientes a los casos prácticos.

## Particularidad de Zeek

Aunque `zeek-live` está definido en el Compose, el Caso 2 recrea deliberadamente el contenedor con la receta validada para limpiar estado y evitar que la supresión de `NOTICE` de ejecuciones anteriores afecte a la prueba.

Por este motivo es normal que el identificador de contenedor y su MAC cambien durante una ejecución del Caso 2.

## Conpot

El despliegue validado de Conpot:

- utiliza `honeynet/conpot:latest`;
- usa la plantilla predeterminada incluida en la imagen;
- no monta las plantillas locales del repositorio;
- publica TCP/502 y TCP/8080 en el host;
- envía los logs mediante syslog UDP/514 a Wazuh Manager.

Los XML presentes en `conpot/` deben considerarse material auxiliar y no la configuración efectiva del contenedor validado.

## Parada

```powershell
docker compose --env-file docker\.env -f docker\docker-compose.yml down
```

## Nota sobre portabilidad

El Compose permite utilizar rutas distintas mediante `.env`. Sin embargo, el laboratorio original comparte logs con la VM del agente Wazuh utilizando las rutas del entorno `C:\tfg`.

Si se migra todo el laboratorio a otra carpeta, deben actualizarse también los recursos compartidos con la VM para que el agente continúe leyendo `eve.json` y `notice.log`.
