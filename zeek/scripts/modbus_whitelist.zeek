##! modbus_whitelist.zeek - Logica de control de acceso Modbus (SOC tranvia).
##! Consulta un DICCIONARIO EXTERNO de acceso (modbus_acl.zeek): la politica se
##! mantiene editando datos, sin tocar esta logica.
##!
##! Tres capas:
##!   1. Interlocutor (modbus_message): solo los servidores SCADA (NIC de sondeo
##!      192.168.5.101/.102) pueden iniciar Modbus, y solo contra un esclavo de
##!      192.168.12.0/24 (subestaciones/CIT) o 192.168.5.0/24 (paradas).
##!   2. Lectura por TABLA/DISPOSITIVO: se alerta si un maestro lee una tabla que
##!      el equipo destino no expone (o un equipo sin entradas en la ACL). No se
##!      valida registro a registro, para no generar ruido en el sondeo por bloques.
##!   3. Escritura por REGISTRO: cada registro escrito se valida contra la ACL.
##!
##! NOTA: las ordenes de bit (abrir/cerrar/desbloqueo/seccionador...) comparten
##! registro (324/325/326); Modbus escribe el registro completo, asi que la ACL
##! autoriza la escritura a nivel de registro, no de bit.
##!
##! Ejecutar:  zeek -C -r captura.pcap modbus_acl.zeek   (el ACL hace @load de este)
##! Verificar offset:  cat modbus.log | zeek-cut id.orig_h id.resp_h func address

module ModbusWhitelist;

export {
    redef enum Notice::Type += {
        UnauthorizedModbusPeer,
        UnauthorizedRead,
        UnauthorizedWrite,
    };
	
	redef Notice::not_suppressed_types += {
		ModbusWhitelist::UnauthorizedModbusPeer,
		ModbusWhitelist::UnauthorizedRead,
		ModbusWhitelist::UnauthorizedWrite
	};


    type AclVal: record {
        rd: bool &default=F;   # lectura permitida
        wr: bool &default=F;   # escritura permitida
    };

    # Diccionario externo de ESCRITURA: [IP destino, tabla, registro] -> permisos.
    # Se rellena en modbus_acl.zeek (desde el PEM).
    global acl: table[addr, string, count] of AclVal &redef;

    # Mapa de LECTURA (Capa 2): (IP destino, tabla) que el equipo expone para
    # lectura. Se rellena en modbus_reads.zeek (corroborado del baseline).
    global read_exposed: set[addr, string] &redef;
}

event zeek_init()
{
    # Las tablas con registros escribibles tambien son legibles: union en read_exposed.
    for ( [d, t, r] in acl )
        add read_exposed[d, t];
}

# --- Capa 1: interlocutores autorizados ---
const scada_masters: set[addr] = { 192.168.5.101, 192.168.5.102 } &redef;
const plc_net_sub:      subnet = 192.168.12.0/24 &redef;
const plc_net_par:      subnet = 192.168.5.0/24 &redef;

function peer_ok(c: connection): bool
{
    if ( c$id$orig_h !in scada_masters ) return F;
    if ( c$id$resp_h !in plc_net_sub && c$id$resp_h !in plc_net_par ) return F;
    return T;
}

event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
{
    if ( ! is_orig ) return;
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    if ( src !in scada_masters )
        NOTICE([$note=UnauthorizedModbusPeer,
                $msg=fmt("Origen Modbus no autorizado: %s -> %s (func=%d)", src, dst, headers$function_code),
                $conn=c, $identifier=cat("peer-src:",src,"->",dst)]);
    else if ( dst !in plc_net_sub && dst !in plc_net_par )
        NOTICE([$note=UnauthorizedModbusPeer,
                $msg=fmt("Destino Modbus fuera de segmento: %s -> %s (func=%d)", src, dst, headers$function_code),
                $conn=c, $identifier=cat("peer-dst:",src,"->",dst)]);
}

# --- Capa 2: LECTURA por tabla/dispositivo ---
function check_read(c: connection, tbl: string)
{
    if ( ! peer_ok(c) ) return;   # interlocutor no autorizado ya lo cubre la Capa 1
    local dst = c$id$resp_h;
    if ( [dst, tbl] !in read_exposed )
        NOTICE([$note=UnauthorizedRead,
                $msg=fmt("Lectura Modbus a tabla/equipo no expuesto: dst=%s tabla=%s", dst, tbl),
                $conn=c, $identifier=cat("r:",dst,":",tbl)]);
}

event modbus_read_coils_request(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
{ check_read(c, "coil"); }

event modbus_read_discrete_inputs_request(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
{ check_read(c, "discrete"); }

event modbus_read_holding_registers_request(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
{ check_read(c, "holding"); }

event modbus_read_input_registers_request(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
{ check_read(c, "input"); }

# --- Capa 3: ESCRITURA por registro ---
function check_write(c: connection, tbl: string, start: count, quantity: count)
{
    if ( ! peer_ok(c) ) return;
    local dst = c$id$resp_h;
    local i = 0;
    while ( i < quantity )
    {
        local reg = start + i;
        local ok = ( [dst, tbl, reg] in acl ) ? acl[dst, tbl, reg]$wr : F;
        if ( ! ok )
            NOTICE([$note=UnauthorizedWrite,
                    $msg=fmt("Escritura Modbus no autorizada: dst=%s tabla=%s reg=%d", dst, tbl, reg),
                    $conn=c, $identifier=cat("w:",dst,":",tbl,":",reg)]);
        i += 1;
    }
}

event modbus_write_single_register_request(c: connection, headers: ModbusHeaders, address: count, value: count)
{ check_write(c, "holding", address, 1); }

event modbus_write_multiple_registers_request(c: connection, headers: ModbusHeaders, start_address: count, registers: ModbusRegisters)
{ check_write(c, "holding", start_address, |registers|); }

# Escritura de COILS: firma variable entre versiones de Zeek; las paradas/CIT son
# solo lectura y cualquier escritura desde un no-maestro ya la marca la Capa 1.
# Descomentar y ajustar la firma a tu version si quieres cubrir tambien al maestro:
# event modbus_write_single_coil_request(c: connection, headers: ModbusHeaders, address: count, value: bool)
# { check_write(c, "coil", address, 1); }
# event modbus_write_multiple_coils_request(c: connection, headers: ModbusHeaders, start_address: count, coils: ModbusCoils)
# { check_write(c, "coil", start_address, |coils|); }
