import hashlib

def hash_b6(flow_6_tuple):
    # (ip_src, ip_dst, ip_proto, tp_src, tp_dst, timestamp)
    ip_a = flow_6_tuple[0]
    ip_b = flow_6_tuple[1]
    proto = int(flow_6_tuple[2])
    tp_src = flow_6_tuple[3]
    tp_dst = flow_6_tuple[4]
    timestamp = flow_6_tuple[5]
    
    # Assign arbitrary consistent direction:
    if ip_a > ip_b:
        direction = 1
    elif ip_b > ip_a:
        direction = 2
    elif tp_src > tp_dst:
        direction = 1
    elif tp_dst > tp_src:
        direction = 2
    else:
        direction = 1

    if direction == 1:
        flow_tuple = (ip_a, ip_b, proto, tp_src, tp_dst, timestamp)
    else:
        # change IPs and port numbers for reverse packets:
        flow_tuple = (ip_b, ip_a, proto, tp_dst, tp_src, timestamp)
    return real_hash(flow_tuple)

def hash_b5(flow_5_tuple):
    # (ip_src, ip_dst, ip_proto, tp_src, tp_dst)
    ip_a = flow_5_tuple[0]
    ip_b = flow_5_tuple[1]
    proto = int(flow_5_tuple[2])
    tp_src = flow_5_tuple[3]
    tp_dst = flow_5_tuple[4]
    
    # Assign arbitrary consistent direction:
    if ip_a > ip_b:
        direction = 1
    elif ip_b > ip_a:
        direction = 2
    elif tp_src > tp_dst:
        direction = 1
    elif tp_dst > tp_src:
        direction = 2
    else:
        direction = 1

    if direction == 1:
        flow_tuple = (ip_a, ip_b, proto, tp_src, tp_dst)
    else:
        # change IPs and port numbers for reverse packets:
        flow_tuple = (ip_b, ip_a, proto, tp_dst, tp_src)
    return real_hash(flow_tuple)

def hash_b3(flow_3_tuple):
    # (ip_src, ip_dst, ip_proto)
    ip_a = flow_3_tuple[0]
    ip_b = flow_3_tuple[1]
    proto = int(flow_3_tuple[2])
    
    # Assign arbitrary consistent direction:
    if ip_a > ip_b:
        direction = 1
    elif ip_b > ip_a:
        direction = 2
    else:
        direction = 1

    if direction == 1:
        flow_tuple = (ip_a, ip_b, proto)
    else:
        # change IPs for reverse packets:
        flow_tuple = (ip_b, ip_a, proto)
    return real_hash(flow_tuple)

def real_hash(hash_tuple):
    r = hashlib.sha224()

    tuple_as_string = str(hash_tuple)
    r.update(tuple_as_string.encode('utf-8'))
    return r.hexdigest()
