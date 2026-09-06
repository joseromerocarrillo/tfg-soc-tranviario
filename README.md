# SOC para redes multiservicio en sistemas tranviarios

Repositorio asociado al Trabajo Fin de Grado:

**«Diseño e implementación de un SOC para redes multiservicio en sistemas tranviarios mediante herramientas open-source: caso práctico con Wazuh»**

**Autor:** José Romero Carrillo  
**Escuela Técnica Superior de Ingeniería — Universidad de Sevilla**  
**Año:** 2026

---

## Descripción

Este repositorio contiene los principales artefactos desarrollados para el diseño, implementación y validación experimental de un Security Operations Center (SOC) aplicado a una red multiservicio de ámbito tranviario.

La propuesta combina herramientas open-source de monitorización y detección con mecanismos específicos para entornos OT, incorporando tanto análisis de tráfico de red como supervisión de eventos generados en los propios sistemas.

La arquitectura experimental integra principalmente:

- **Wazuh**, como plataforma central de monitorización, correlación y visualización de alertas.
- **Suricata**, como IDS de red para la detección basada en firmas y comportamiento.
- **Zeek**, para el análisis semántico de comunicaciones y la aplicación de políticas específicas sobre Modbus/TCP.
- **Conpot**, como honeypot industrial para la simulación de servicios OT.
- **Docker**, utilizado para desplegar y aislar varios componentes del laboratorio.
- **PowerShell y scripts auxiliares**, empleados para automatizar la reproducción de los escenarios de validación.

El repositorio reúne reglas, configuraciones, scripts, capturas sintéticas y resultados derivados utilizados durante el desarrollo del trabajo.

---

## Objetivos del repositorio

El objetivo principal es proporcionar los elementos necesarios para comprender y reproducir, en la medida de lo posible, los casos prácticos desarrollados en el TFG.

Se incluyen:

- reglas personalizadas de Wazuh;
- firmas y configuración de Suricata;
- scripts de análisis y detección con Zeek;
- configuración del honeypot Conpot;
- scripts de automatización y reproducción;
- PCAP generados específicamente para el laboratorio;
- resultados derivados del análisis del dataset real;
- documentación auxiliar de los escenarios.

Las capturas procedentes de la infraestructura tranviaria real no se publican.

---

## Arquitectura del laboratorio

El laboratorio utilizado para la validación combina máquinas virtuales y contenedores Docker.

La plataforma Wazuh centraliza los eventos generados por los distintos mecanismos de detección, permitiendo disponer de una vista común de alertas procedentes tanto de fuentes de red como de host.

Entre los componentes utilizados se encuentran:

| Componente | Función principal |
|---|---|
| Wazuh Manager | Procesamiento y correlación de eventos |
| Wazuh Indexer | Almacenamiento e indexación |
| Wazuh Dashboard | Visualización y análisis |
| Wazuh Agent | Recogida de eventos de host y FIM |
| Suricata | IDS y análisis de tráfico de red |
| Zeek | Análisis semántico y políticas Modbus/TCP |
| Conpot | Honeypot para protocolos industriales |
| vsftpd | Servicio FTP utilizado en la validación FIM |
| OpenSSH | Servicio utilizado en las pruebas de acceso SSH |

---

## Casos prácticos

El laboratorio implementa los siguientes escenarios de detección:

### Caso 1 — Interacción con honeypot industrial

Se utiliza Conpot para simular un dispositivo industrial accesible mediante Modbus/TCP.

Wazuh procesa los eventos generados por el honeypot y permite identificar conexiones, peticiones Modbus y excepciones producidas durante la interacción.

### Caso 2 — Control de comunicaciones Modbus con Zeek

Zeek analiza las comunicaciones Modbus/TCP y aplica una política de control basada en:

- interlocutores autorizados;
- tipo de operación;
- tabla Modbus;
- direcciones y registros permitidos.

Se detectan, entre otros escenarios:

- comunicaciones procedentes de interlocutores Modbus no autorizados;
- escrituras sobre registros no permitidos;
- lecturas que incumplan la política definida.

### Caso 3 — Movimiento lateral entre Ofimática y SCADA

Suricata detecta comunicaciones desde la red de Ofimática hacia servicios sensibles del entorno SCADA.

Los servicios evaluados incluyen:

- SMB — TCP/445;
- SQL Server — TCP/1433;
- Modbus/TCP — TCP/502;
- RDP — TCP/3389.

### Caso 4 — Monitorización de integridad de ficheros

El agente Wazuh supervisa en tiempo real un directorio utilizado como repositorio de contenidos FTP.

La creación o modificación de ficheros mediante el servicio FTP genera eventos FIM que son procesados por Wazuh.

### Caso 5 — Acceso SSH fuera de la ventana temporal definida

Se supervisan autenticaciones SSH correctas realizadas fuera del periodo temporal establecido.

La detección combina los eventos nativos de OpenSSH con una regla temporal personalizada en Wazuh.

### Caso 5b — Inspección DPI y discordancia protocolo/puerto

Suricata analiza el protocolo de aplicación observado y lo compara con el servicio esperado para determinados puertos.

Se incluyen escenarios como:

- tráfico no Modbus utilizando TCP/502;
- tráfico no RDP utilizando TCP/3389;
- comunicaciones cuya identificación de protocolo resulta inconsistente o fallida.

### Caso 6 — Detección de escaneos

Se evalúan dos patrones de reconocimiento:

- escaneo vertical de puertos TCP;
- barrido de múltiples hosts desde un mismo origen.

### Caso 7 — Detección de patrones compatibles con fuerza bruta SSH

Suricata identifica un número elevado de conexiones o sesiones SSH repetidas desde un mismo origen.

Wazuh recibe estos eventos y puede elevar su criticidad cuando se producen dentro de la ventana temporal definida por la política del laboratorio.

---

## Estructura del repositorio

```text
.
├── conpot/
│   ├── template.xml
│   └── templates/
│
├── docs/
│   ├── CASO_1_HONEYPOT_CONPOT_WAZUH_REPRODUCCION.md
│   ├── GUIA_REPRODUCCION_CASOS_1-5_LIVE_TFG.md
│   ├── GUIA_REPRODUCCION_SURICATA_TFG_ACTUALIZADA.md
│   └── ejecutar ataques con script.txt
│
├── pcaps-synthetic/
│   ├── ataque_modbus.pcap
│   ├── binario_aleatorio_3389.pcap
│   ├── escaneo_activos_servicios.pcap
│   ├── http_en_502.pcap
│   ├── movimiento_lateral.pcap
│   ├── ssh_bruteforce_billetaje.pcap
│   └── ssh_en_8080.pcap
│
├── scripts/
│   ├── Invoke-CasosPracticos.ps1
│   └── filtrar_trafico.ps1
│
├── suricata/
│   ├── config/
│   │   └── suricata.yaml
│   ├── rules/
│   │   ├── lateral_movement.rules
│   │   └── local.rules
│   ├── docker_run.txt
│   ├── movimiento_lateral.py
│   └── suricata-minimal.yaml
│
├── wazuh/
│   └── rules/
│       └── local_rules.xml
│
└── zeek/
    ├── results/
    │   ├── modbus_address_profile.csv
    │   └── reconciliacion.txt
    ├── scripts/
    │   ├── gen_acl.py
    │   ├── modbus_acl.zeek
    │   ├── modbus_profile.zeek
    │   ├── modbus_whitelist.zeek
    │   └── run_live_zeek.sh
    └── lanzar docker y pruebas.txt