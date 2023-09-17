import socket

def send(sock: socket.socket, data: bytes):
    block_byte_count = 0
    for d in data:
        sock.send(d.to_bytes(1, 'little'))
        block_byte_count += 1

        if block_byte_count >= 15:
            ack_reply = recv(sock, 1)
            if ack_reply != b'Z':
                raise RuntimeError("protocol violation: bad ACK response (%s)" % ack_reply)
            block_byte_count = 0

def recv(sock: socket.socket, byte_limit: int):
    buf = b''
    num_bytes_received = 0
    block_byte_count = 0

    while True:
        if byte_limit is not None and num_bytes_received >= byte_limit:
            break
        try:
            buf += sock.recv(1)
            block_byte_count += 1
            if block_byte_count >= 15:
                send(sock, b'Z')
                block_byte_count = 0
            num_bytes_received += 1
        except socket.timeout:
            break
    return buf
