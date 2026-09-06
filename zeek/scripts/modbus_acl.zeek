##! modbus_acl.zeek - DICCIONARIO UNICO de acceso Modbus (generado del
##! LISTADO_IPS_PEM). Lectura: toda IP documentada por su tabla. Escritura:
##! registros de mando en equipos comandables (anillo/feeder/grupo/secc).
##! Regenerar:  python3 gen_acl.py LISTADO_IPS_PEM.xlsx > modbus_acl.zeek

@load ./modbus_whitelist
module ModbusACL;

# --- LECTURA (Capa 2): (IP, tabla) que cada equipo expone ---
redef ModbusWhitelist::read_exposed += {
    # ANILLO 1
    [192.168.12.121, "holding"],
    # ANILLO 2
    [192.168.12.122, "holding"],
    # FEEDER 1
    [192.168.12.23, "holding"],
    # FEEDER 2
    [192.168.12.24, "holding"],
    # GRUPO 1
    [192.168.12.21, "holding"],
    # GRUPO 2
    [192.168.12.22, "holding"],
    # RET
    [192.168.12.26, "holding"],
    # SA
    [192.168.12.29, "holding"],
    # SECC
    [192.168.12.25, "holding"],
    # ANILLO 1
    [192.168.12.131, "holding"],
    # ANILLO 2
    [192.168.12.132, "holding"],
    # FEEDER 1
    [192.168.12.33, "holding"],
    # FEEDER 2
    [192.168.12.34, "holding"],
    # GRUPO 1
    [192.168.12.31, "holding"],
    # RET
    [192.168.12.36, "holding"],
    # SA
    [192.168.12.39, "holding"],
    # SECC
    [192.168.12.35, "holding"],
    # ANILLO 1
    [192.168.12.141, "holding"],
    # ANILLO 2
    [192.168.12.142, "holding"],
    # FEEDER 1
    [192.168.12.43, "holding"],
    # GRUPO 1
    [192.168.12.41, "holding"],
    # ACOMETIDA 1
    [192.168.12.149, "holding"],
    # ACOMETIDA 2
    [192.168.12.148, "holding"],
    # SA
    [192.168.12.49, "holding"],
    # SECC
    [192.168.12.45, "holding"],
    # TYC
    [192.168.12.143, "holding"],
    # SECC Y CONT
    [192.168.12.14, "holding"],
    # RET
    [192.168.12.46, "holding"],
    # UNICO PLC
    [192.168.12.60, "holding"],
    # CONEXION C.I.T. 1
    [192.168.12.71, "discrete"],
    [192.168.12.71, "coil"],
    # CONEXION C.I.T. 2
    [192.168.12.72, "discrete"],
    [192.168.12.72, "coil"],
    # CONEXION C.I.T. 3
    [192.168.12.73, "discrete"],
    [192.168.12.73, "coil"],
    # REMOTA PARADA 1
    [192.168.5.1, "coil"],
    # REMOTA PARADA 2
    [192.168.5.2, "coil"],
    # REMOTA PARADA 3
    [192.168.5.3, "coil"],
    # REMOTA PARADA 4
    [192.168.5.4, "coil"],
    # REMOTA PARADA 5
    [192.168.5.5, "coil"],
    # REMOTA PARADA 6
    [192.168.5.6, "coil"],
    # REMOTA PARADA 7
    [192.168.5.7, "coil"],
    # REMOTA PARADA 8
    [192.168.5.8, "coil"],
    # REMOTA PARADA 9
    [192.168.5.9, "coil"],
    # REMOTA PARADA 10
    [192.168.5.10, "coil"],
    # IPs vistas en el trafico pero NO en el listado PEM (confirmar equipo):
    [192.168.12.20, "holding"],   # observado, no documentado
    [192.168.12.30, "holding"],   # observado, no documentado
    [192.168.12.40, "holding"],   # observado, no documentado
};

# --- ESCRITURA (Capa 3): registros de mando por equipo comandable ---
# Supuesto: los equipos comandables comparten el mapa de registros de ORDEN
# del PEM de senales (324/325/326) + reloj (60-65); SET usa 103/324. Confirmar
# con las senales por equipo si se dispone de ellas.
redef ModbusWhitelist::acl += {
    # ANILLO 1
    [192.168.12.121, "holding", 324] = [$rd=T, $wr=T],
    [192.168.12.121, "holding", 325] = [$rd=T, $wr=T],
    [192.168.12.121, "holding", 326] = [$rd=T, $wr=T],
    [192.168.12.121, "holding", 60] = [$rd=T, $wr=T],
    [192.168.12.121, "holding", 61] = [$rd=T, $wr=T],
    [192.168.12.121, "holding", 62] = [$rd=T, $wr=T],
    [192.168.12.121, "holding", 63] = [$rd=T, $wr=T],
    [192.168.12.121, "holding", 64] = [$rd=T, $wr=T],
    [192.168.12.121, "holding", 65] = [$rd=T, $wr=T],
    # ANILLO 2
    [192.168.12.122, "holding", 324] = [$rd=T, $wr=T],
    [192.168.12.122, "holding", 325] = [$rd=T, $wr=T],
    [192.168.12.122, "holding", 326] = [$rd=T, $wr=T],
    [192.168.12.122, "holding", 60] = [$rd=T, $wr=T],
    [192.168.12.122, "holding", 61] = [$rd=T, $wr=T],
    [192.168.12.122, "holding", 62] = [$rd=T, $wr=T],
    [192.168.12.122, "holding", 63] = [$rd=T, $wr=T],
    [192.168.12.122, "holding", 64] = [$rd=T, $wr=T],
    [192.168.12.122, "holding", 65] = [$rd=T, $wr=T],
    # FEEDER 1
    [192.168.12.23, "holding", 324] = [$rd=T, $wr=T],
    [192.168.12.23, "holding", 325] = [$rd=T, $wr=T],
    [192.168.12.23, "holding", 326] = [$rd=T, $wr=T],
    [192.168.12.23, "holding", 60] = [$rd=T, $wr=T],
    [192.168.12.23, "holding", 61] = [$rd=T, $wr=T],
    [192.168.12.23, "holding", 62] = [$rd=T, $wr=T],
    [192.168.12.23, "holding", 63] = [$rd=T, $wr=T],
    [192.168.12.23, "holding", 64] = [$rd=T, $wr=T],
    [192.168.12.23, "holding", 65] = [$rd=T, $wr=T],
    # FEEDER 2
    [192.168.12.24, "holding", 324] = [$rd=T, $wr=T],
    [192.168.12.24, "holding", 325] = [$rd=T, $wr=T],
    [192.168.12.24, "holding", 326] = [$rd=T, $wr=T],
    [192.168.12.24, "holding", 60] = [$rd=T, $wr=T],
    [192.168.12.24, "holding", 61] = [$rd=T, $wr=T],
    [192.168.12.24, "holding", 62] = [$rd=T, $wr=T],
    [192.168.12.24, "holding", 63] = [$rd=T, $wr=T],
    [192.168.12.24, "holding", 64] = [$rd=T, $wr=T],
    [192.168.12.24, "holding", 65] = [$rd=T, $wr=T],
    # GRUPO 1
    [192.168.12.21, "holding", 324] = [$rd=T, $wr=T],
    [192.168.12.21, "holding", 325] = [$rd=T, $wr=T],
    [192.168.12.21, "holding", 326] = [$rd=T, $wr=T],
    [192.168.12.21, "holding", 60] = [$rd=T, $wr=T],
    [192.168.12.21, "holding", 61] = [$rd=T, $wr=T],
    [192.168.12.21, "holding", 62] = [$rd=T, $wr=T],
    [192.168.12.21, "holding", 63] = [$rd=T, $wr=T],
    [192.168.12.21, "holding", 64] = [$rd=T, $wr=T],
    [192.168.12.21, "holding", 65] = [$rd=T, $wr=T],
    # GRUPO 2
    [192.168.12.22, "holding", 324] = [$rd=T, $wr=T],
    [192.168.12.22, "holding", 325] = [$rd=T, $wr=T],
    [192.168.12.22, "holding", 326] = [$rd=T, $wr=T],
    [192.168.12.22, "holding", 60] = [$rd=T, $wr=T],
    [192.168.12.22, "holding", 61] = [$rd=T, $wr=T],
    [192.168.12.22, "holding", 62] = [$rd=T, $wr=T],
    [192.168.12.22, "holding", 63] = [$rd=T, $wr=T],
    [192.168.12.22, "holding", 64] = [$rd=T, $wr=T],
    [192.168.12.22, "holding", 65] = [$rd=T, $wr=T],
    # SECC
    [192.168.12.25, "holding", 324] = [$rd=T, $wr=T],
    [192.168.12.25, "holding", 325] = [$rd=T, $wr=T],
    [192.168.12.25, "holding", 326] = [$rd=T, $wr=T],
    [192.168.12.25, "holding", 60] = [$rd=T, $wr=T],
    [192.168.12.25, "holding", 61] = [$rd=T, $wr=T],
    [192.168.12.25, "holding", 62] = [$rd=T, $wr=T],
    [192.168.12.25, "holding", 63] = [$rd=T, $wr=T],
    [192.168.12.25, "holding", 64] = [$rd=T, $wr=T],
    [192.168.12.25, "holding", 65] = [$rd=T, $wr=T],
    # ANILLO 1
    [192.168.12.131, "holding", 324] = [$rd=T, $wr=T],
    [192.168.12.131, "holding", 325] = [$rd=T, $wr=T],
    [192.168.12.131, "holding", 326] = [$rd=T, $wr=T],
    [192.168.12.131, "holding", 60] = [$rd=T, $wr=T],
    [192.168.12.131, "holding", 61] = [$rd=T, $wr=T],
    [192.168.12.131, "holding", 62] = [$rd=T, $wr=T],
    [192.168.12.131, "holding", 63] = [$rd=T, $wr=T],
    [192.168.12.131, "holding", 64] = [$rd=T, $wr=T],
    [192.168.12.131, "holding", 65] = [$rd=T, $wr=T],
    # ANILLO 2
    [192.168.12.132, "holding", 324] = [$rd=T, $wr=T],
    [192.168.12.132, "holding", 325] = [$rd=T, $wr=T],
    [192.168.12.132, "holding", 326] = [$rd=T, $wr=T],
    [192.168.12.132, "holding", 60] = [$rd=T, $wr=T],
    [192.168.12.132, "holding", 61] = [$rd=T, $wr=T],
    [192.168.12.132, "holding", 62] = [$rd=T, $wr=T],
    [192.168.12.132, "holding", 63] = [$rd=T, $wr=T],
    [192.168.12.132, "holding", 64] = [$rd=T, $wr=T],
    [192.168.12.132, "holding", 65] = [$rd=T, $wr=T],
    # FEEDER 1
    [192.168.12.33, "holding", 324] = [$rd=T, $wr=T],
    [192.168.12.33, "holding", 325] = [$rd=T, $wr=T],
    [192.168.12.33, "holding", 326] = [$rd=T, $wr=T],
    [192.168.12.33, "holding", 60] = [$rd=T, $wr=T],
    [192.168.12.33, "holding", 61] = [$rd=T, $wr=T],
    [192.168.12.33, "holding", 62] = [$rd=T, $wr=T],
    [192.168.12.33, "holding", 63] = [$rd=T, $wr=T],
    [192.168.12.33, "holding", 64] = [$rd=T, $wr=T],
    [192.168.12.33, "holding", 65] = [$rd=T, $wr=T],
    # FEEDER 2
    [192.168.12.34, "holding", 324] = [$rd=T, $wr=T],
    [192.168.12.34, "holding", 325] = [$rd=T, $wr=T],
    [192.168.12.34, "holding", 326] = [$rd=T, $wr=T],
    [192.168.12.34, "holding", 60] = [$rd=T, $wr=T],
    [192.168.12.34, "holding", 61] = [$rd=T, $wr=T],
    [192.168.12.34, "holding", 62] = [$rd=T, $wr=T],
    [192.168.12.34, "holding", 63] = [$rd=T, $wr=T],
    [192.168.12.34, "holding", 64] = [$rd=T, $wr=T],
    [192.168.12.34, "holding", 65] = [$rd=T, $wr=T],
    # GRUPO 1
    [192.168.12.31, "holding", 324] = [$rd=T, $wr=T],
    [192.168.12.31, "holding", 325] = [$rd=T, $wr=T],
    [192.168.12.31, "holding", 326] = [$rd=T, $wr=T],
    [192.168.12.31, "holding", 60] = [$rd=T, $wr=T],
    [192.168.12.31, "holding", 61] = [$rd=T, $wr=T],
    [192.168.12.31, "holding", 62] = [$rd=T, $wr=T],
    [192.168.12.31, "holding", 63] = [$rd=T, $wr=T],
    [192.168.12.31, "holding", 64] = [$rd=T, $wr=T],
    [192.168.12.31, "holding", 65] = [$rd=T, $wr=T],
    # SECC
    [192.168.12.35, "holding", 324] = [$rd=T, $wr=T],
    [192.168.12.35, "holding", 325] = [$rd=T, $wr=T],
    [192.168.12.35, "holding", 326] = [$rd=T, $wr=T],
    [192.168.12.35, "holding", 60] = [$rd=T, $wr=T],
    [192.168.12.35, "holding", 61] = [$rd=T, $wr=T],
    [192.168.12.35, "holding", 62] = [$rd=T, $wr=T],
    [192.168.12.35, "holding", 63] = [$rd=T, $wr=T],
    [192.168.12.35, "holding", 64] = [$rd=T, $wr=T],
    [192.168.12.35, "holding", 65] = [$rd=T, $wr=T],
    # ANILLO 1
    [192.168.12.141, "holding", 324] = [$rd=T, $wr=T],
    [192.168.12.141, "holding", 325] = [$rd=T, $wr=T],
    [192.168.12.141, "holding", 326] = [$rd=T, $wr=T],
    [192.168.12.141, "holding", 60] = [$rd=T, $wr=T],
    [192.168.12.141, "holding", 61] = [$rd=T, $wr=T],
    [192.168.12.141, "holding", 62] = [$rd=T, $wr=T],
    [192.168.12.141, "holding", 63] = [$rd=T, $wr=T],
    [192.168.12.141, "holding", 64] = [$rd=T, $wr=T],
    [192.168.12.141, "holding", 65] = [$rd=T, $wr=T],
    # ANILLO 2
    [192.168.12.142, "holding", 324] = [$rd=T, $wr=T],
    [192.168.12.142, "holding", 325] = [$rd=T, $wr=T],
    [192.168.12.142, "holding", 326] = [$rd=T, $wr=T],
    [192.168.12.142, "holding", 60] = [$rd=T, $wr=T],
    [192.168.12.142, "holding", 61] = [$rd=T, $wr=T],
    [192.168.12.142, "holding", 62] = [$rd=T, $wr=T],
    [192.168.12.142, "holding", 63] = [$rd=T, $wr=T],
    [192.168.12.142, "holding", 64] = [$rd=T, $wr=T],
    [192.168.12.142, "holding", 65] = [$rd=T, $wr=T],
    # FEEDER 1
    [192.168.12.43, "holding", 324] = [$rd=T, $wr=T],
    [192.168.12.43, "holding", 325] = [$rd=T, $wr=T],
    [192.168.12.43, "holding", 326] = [$rd=T, $wr=T],
    [192.168.12.43, "holding", 60] = [$rd=T, $wr=T],
    [192.168.12.43, "holding", 61] = [$rd=T, $wr=T],
    [192.168.12.43, "holding", 62] = [$rd=T, $wr=T],
    [192.168.12.43, "holding", 63] = [$rd=T, $wr=T],
    [192.168.12.43, "holding", 64] = [$rd=T, $wr=T],
    [192.168.12.43, "holding", 65] = [$rd=T, $wr=T],
    # GRUPO 1
    [192.168.12.41, "holding", 324] = [$rd=T, $wr=T],
    [192.168.12.41, "holding", 325] = [$rd=T, $wr=T],
    [192.168.12.41, "holding", 326] = [$rd=T, $wr=T],
    [192.168.12.41, "holding", 60] = [$rd=T, $wr=T],
    [192.168.12.41, "holding", 61] = [$rd=T, $wr=T],
    [192.168.12.41, "holding", 62] = [$rd=T, $wr=T],
    [192.168.12.41, "holding", 63] = [$rd=T, $wr=T],
    [192.168.12.41, "holding", 64] = [$rd=T, $wr=T],
    [192.168.12.41, "holding", 65] = [$rd=T, $wr=T],
    # SECC
    [192.168.12.45, "holding", 324] = [$rd=T, $wr=T],
    [192.168.12.45, "holding", 325] = [$rd=T, $wr=T],
    [192.168.12.45, "holding", 326] = [$rd=T, $wr=T],
    [192.168.12.45, "holding", 60] = [$rd=T, $wr=T],
    [192.168.12.45, "holding", 61] = [$rd=T, $wr=T],
    [192.168.12.45, "holding", 62] = [$rd=T, $wr=T],
    [192.168.12.45, "holding", 63] = [$rd=T, $wr=T],
    [192.168.12.45, "holding", 64] = [$rd=T, $wr=T],
    [192.168.12.45, "holding", 65] = [$rd=T, $wr=T],
    # SECC Y CONT
    [192.168.12.14, "holding", 324] = [$rd=T, $wr=T],
    [192.168.12.14, "holding", 325] = [$rd=T, $wr=T],
    [192.168.12.14, "holding", 326] = [$rd=T, $wr=T],
    [192.168.12.14, "holding", 60] = [$rd=T, $wr=T],
    [192.168.12.14, "holding", 61] = [$rd=T, $wr=T],
    [192.168.12.14, "holding", 62] = [$rd=T, $wr=T],
    [192.168.12.14, "holding", 63] = [$rd=T, $wr=T],
    [192.168.12.14, "holding", 64] = [$rd=T, $wr=T],
    [192.168.12.14, "holding", 65] = [$rd=T, $wr=T],
    # UNICO PLC
    [192.168.12.60, "holding", 103] = [$rd=T, $wr=T],
    [192.168.12.60, "holding", 324] = [$rd=T, $wr=T],
    [192.168.12.60, "holding", 60] = [$rd=T, $wr=T],
    [192.168.12.60, "holding", 61] = [$rd=T, $wr=T],
    [192.168.12.60, "holding", 62] = [$rd=T, $wr=T],
    [192.168.12.60, "holding", 63] = [$rd=T, $wr=T],
    [192.168.12.60, "holding", 64] = [$rd=T, $wr=T],
    [192.168.12.60, "holding", 65] = [$rd=T, $wr=T],
};
