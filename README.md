# SOC para redes multiservicio en sistemas tranviarios

Repositorio asociado al Trabajo Fin de Grado:

**“Diseño e implementación de un SOC para redes multiservicio en sistemas tranviarios mediante herramientas open-source: caso práctico con Wazuh”**

## Descripción

Este repositorio contiene los principales artefactos desarrollados para la implementación y validación de un SOC orientado a una red multiservicio de ámbito tranviario.

La solución integra:

- Wazuh como plataforma central de monitorización y correlación.
- Suricata para detección de amenazas a nivel de red.
- Zeek para análisis y monitorización de protocolos, incluyendo Modbus/TCP.
- Conpot como honeypot industrial.
- Scripts de generación, reproducción y validación de los casos prácticos.

## Contenido

- `wazuh/`: reglas de correlación utilizadas en Wazuh.
- `suricata/`: configuración y reglas de detección.
- `zeek/`: scripts de análisis Modbus y resultados derivados.
- `conpot/`: configuración del honeypot industrial.
- `scripts/`: scripts auxiliares de reproducción y procesamiento.
- `docs/`: documentación de reproducción de los escenarios.

## Casos prácticos

1. Interacción con honeypot industrial Conpot.
2. Control de comunicaciones Modbus mediante Zeek.
3. Detección de movimiento lateral entre Ofimática y SCADA.
4. Monitorización de integridad de ficheros.
5. Detección de accesos SSH fuera de la ventana temporal definida.
5b. Detección de discordancias protocolo/puerto mediante DPI.
6. Detección de escaneos de red.
7. Detección de patrones compatibles con fuerza bruta SSH.

## Dataset

Las capturas de tráfico utilizadas durante el trabajo no se distribuyen en este repositorio.

Parte del dataset procede de una infraestructura operacional real y, además,
el conjunto de capturas presenta un volumen elevado. Por este motivo se
publican únicamente los scripts de análisis y los resultados derivados
necesarios para documentar y reproducir la metodología.

Entre los resultados derivados publicados se incluyen:

- caracterización de comunicaciones Modbus/TCP;
- iniciadores y destinos observados;
- códigos de función Modbus;
- rangos de direcciones accedidos;
- resultados agregados utilizados durante la validación.

## Reproducción

Las guías de reproducción se encuentran en el directorio `docs/`.

Los PCAP necesarios para determinadas pruebas no forman parte del repositorio,
por lo que deberán ser proporcionados o generados independientemente cuando
proceda.

## Autor

José Romero Carrillo  
Escuela Técnica Superior de Ingeniería — Universidad de Sevilla  
2026