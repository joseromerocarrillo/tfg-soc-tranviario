#!/bin/bash
##! run_live_zeek.sh - Zeek en vivo + tcpreplay (montaje tipo SOC real).
##! tcpreplay inyecta en veth0; Zeek captura en veth1 (mismo netns).
##! Zeek escribe los logs en /logs (carpeta compartida con la VM del agente),
##! anexando a notice.log en vez de truncarlo -> Wazuh lo sigue sin perder lineas.
##!
##! Ejecutar DENTRO del contenedor (ver comando docker mas abajo):
##!   bash /scripts/run_live_zeek.sh /pcaps/ataque_modbus.pcap
set -e
PCAP="${1:-/pcaps/ataque_modbus.pcap}"
SCRIPT="${2:-/scripts/modbus_acl.zeek}"

# 1) Herramientas (solo la primera vez; necesita salida a internet del contenedor)
if ! command -v tcpreplay >/dev/null; then
  apt-get update -qq && apt-get install -y -qq tcpreplay iproute2
fi

# 2) Par veth: veth0 (inyeccion) <-> veth1 (captura)
ip link del veth0 2>/dev/null || true
ip link add veth0 type veth peer name veth1
ip link set veth0 up
ip link set veth1 up

# 3) Zeek en vivo en veth1, logs en /logs (cwd). -C ignora checksums crafteados.
cd /logs
echo "[*] Arrancando Zeek en vivo sobre veth1 ..."
zeek -i veth1 -C "$SCRIPT" &
ZEEK_PID=$!
sleep 3   # que Zeek termine de inicializar y cree los .log

# 4) Reproducir el pcap en veth0 a maxima velocidad
echo "[*] Reproduciendo $PCAP ..."
tcpreplay -i veth0 --topspeed "$PCAP"

sleep 2
echo "[*] Hecho. notice.log:"
[ -f /logs/notice.log ] && grep -c "ModbusWhitelist" /logs/notice.log || echo "  (sin notices)"
echo "[*] Zeek sigue en vivo (PID $ZEEK_PID). Ctrl-C para parar, o relanza tcpreplay para mas trafico."
wait $ZEEK_PID
