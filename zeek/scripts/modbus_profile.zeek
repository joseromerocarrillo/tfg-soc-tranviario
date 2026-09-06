@load base/protocols/modbus

module ModbusProfile;

# Perfil detallado de accesos Modbus/TCP observado en un PCAP.
#
# Salida por stdout en CSV:
# src_ip,dst_ip,function_code,function_name,table_type,start_address,end_address,quantity,count
#
# IMPORTANTE:
# - start_address/end_address son las direcciones PDU Modbus tal como aparecen
#   en el protocolo (offsets base 0).
# - El script agrega peticiones idénticas para no generar millones de filas.
# - Se procesan peticiones de lectura FC1-FC4 y escrituras simples FC5-FC6.
#   El dataset real ya caracterizado solo mostró FC1, FC2 y FC3.

global accesses: table[addr, addr, count, count, count] of count &default=0;

function function_name(fc: count): string
    {
    if ( fc == 1 ) return "Read Coils";
    if ( fc == 2 ) return "Read Discrete Inputs";
    if ( fc == 3 ) return "Read Holding Registers";
    if ( fc == 4 ) return "Read Input Registers";
    if ( fc == 5 ) return "Write Single Coil";
    if ( fc == 6 ) return "Write Single Register";
    return "Other";
    }

function table_name(fc: count): string
    {
    if ( fc == 1 || fc == 5 ) return "coils";
    if ( fc == 2 ) return "discrete_inputs";
    if ( fc == 3 || fc == 6 ) return "holding_registers";
    if ( fc == 4 ) return "input_registers";
    return "unknown";
    }

function add_access(c: connection, fc: count, start_address: count, quantity: count)
    {
    ++accesses[c$id$orig_h, c$id$resp_h, fc, start_address, quantity];
    }

event modbus_read_coils_request(c: connection,
                                headers: ModbusHeaders,
                                start_address: count,
                                quantity: count)
    {
    add_access(c, headers$function_code, start_address, quantity);
    }

event modbus_read_discrete_inputs_request(c: connection,
                                          headers: ModbusHeaders,
                                          start_address: count,
                                          quantity: count)
    {
    add_access(c, headers$function_code, start_address, quantity);
    }

event modbus_read_holding_registers_request(c: connection,
                                            headers: ModbusHeaders,
                                            start_address: count,
                                            quantity: count)
    {
    add_access(c, headers$function_code, start_address, quantity);
    }

event modbus_read_input_registers_request(c: connection,
                                          headers: ModbusHeaders,
                                          start_address: count,
                                          quantity: count)
    {
    add_access(c, headers$function_code, start_address, quantity);
    }

event modbus_write_single_coil_request(c: connection,
                                       headers: ModbusHeaders,
                                       address: count,
                                       value: bool)
    {
    add_access(c, headers$function_code, address, 1);
    }

event modbus_write_single_register_request(c: connection,
                                           headers: ModbusHeaders,
                                           address: count,
                                           value: count)
    {
    add_access(c, headers$function_code, address, 1);
    }

event zeek_done()
    {
    print "src_ip,dst_ip,function_code,function_name,table_type,start_address,end_address,quantity,count";

    for ( [src, dst, fc, start_address, quantity], n in accesses )
        {
        local end_address = start_address + quantity - 1;

        print fmt("%s,%s,%d,%s,%s,%d,%d,%d,%d",
                  src,
                  dst,
                  fc,
                  function_name(fc),
                  table_name(fc),
                  start_address,
                  end_address,
                  quantity,
                  n);
        }
    }
