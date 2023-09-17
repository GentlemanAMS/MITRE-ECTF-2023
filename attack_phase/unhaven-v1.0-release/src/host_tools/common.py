#!/usr/bin/python3 -u
"""
A common Python class for fob connections.

This module handles any encryption and decryption, as well as some common stuff like ACK reception


Also there is an impostor among us
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⣤⣤⣤⣤⣶⣦⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⡿⠛⠉⠙⠛⠛⠛⠛⠻⢿⣿⣷⣤⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⠋⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⠈⢻⣿⣿⡄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣸⣿⡏⠀⠀⠀⣠⣶⣾⣿⣿⣿⠿⠿⠿⢿⣿⣿⣿⣄⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣿⣿⠁⠀⠀⢰⣿⣿⣯⠁⠀⠀⠀⠀⠀⠀⠀⠈⠙⢿⣷⡄⠀
⠀⠀⣀⣤⣴⣶⣶⣿⡟⠀⠀⠀⢸⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣷⠀
⠀⢰⣿⡟⠋⠉⣹⣿⡇⠀⠀⠀⠘⣿⣿⣿⣿⣷⣦⣤⣤⣤⣶⣶⣶⣶⣿⣿⣿⠀
⠀⢸⣿⡇⠀⠀⣿⣿⡇⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠃⠀
⠀⣸⣿⡇⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠉⠻⠿⣿⣿⣿⣿⡿⠿⠿⠛⢻⣿⡇⠀⠀
⠀⣿⣿⠁⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣧⠀⠀
⠀⣿⣿⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀
⠀⣿⣿⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀
⠀⢿⣿⡆⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡇⠀⠀
⠀⠸⣿⣧⡀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠃⠀⠀
⠀⠀⠛⢿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⣰⣿⣿⣷⣶⣶⣶⣶⠶⠀⢠⣿⣿⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⣿⣿⡇⠀⣽⣿⡏⠁⠀⠀⢸⣿⡇⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⣿⣿⡇⠀⢹⣿⡆⠀⠀⠀⣸⣿⠇⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢿⣿⣦⣄⣀⣠⣴⣿⣿⠁⠀⠈⠻⣿⣿⣿⣿⡿⠏⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠛⠻⠿⠿⠿⠿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

import socket
import struct
import secrets
import logging
import crcmod

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import Encoding

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class ReadException(Exception):
    pass


class FobConnection:
    def __init__(self, s: socket.socket):
        self.log = logging.getLogger('device')
        self.crc_def = crcmod.mkCrcFun(0x18005, rev=True, initCrc=0xFFFF, xorOut=0x0000)
        self.s = s

        self.aes_key = None     # type: bytearray
        self.aes_iv = None      # type: bytearray
        self.cipher = None      # type: Cipher

    def receive_frame(self, encrypted: bool = True) -> bytes:
        """
        Receives a frame as per specification and decrypts the data if there is a need for it
        """
        data_len = self._receive_until(1)
        self.log.debug("Data len received: %s", data_len)
        data_len = int.from_bytes(data_len, 'big')

        if data_len > 80:
            self.log.error("Data length is more than 80")
            raise ReadException()

        data_plus_crc = self._receive_until(data_len)
        self.log.debug("Data + CRC: %s", data_plus_crc)

        data = data_plus_crc[:-2]

        device_crc = struct.unpack(">H", data_plus_crc[-2:])[0]
        calc_crc = self.crc_def(data)
        self.log.debug("Received for device CRC: %s, Calc: %s", device_crc, calc_crc)
        if device_crc != calc_crc:
            raise ReadException()

        if encrypted:
            dec = self.cipher.decryptor()
            data = dec.update(data) + dec.finalize()

        return data

    def send_packet(self, command: int, data: bytes = bytes()):
        """
        Sends a packet (command and data) over
        """
        to_send_p = bytearray()
        to_send_p.append(command)
        to_send_p += data

        self.send_frame(to_send_p)

    def send_frame(self, data: bytes, encrypted: bool = True):
        """
        Packs up a frame per specification, encrypts it if desired, and sends it over
        """
        data_len = len(data)
        self.log.debug("Sending Data %s", data)

        if encrypted:
            padding = 16 - (data_len % 16)
            data += bytes(padding)
            data_len = len(data)

            enc = self.cipher.encryptor()
            data = enc.update(data) + enc.finalize()

        to_send = bytearray(1)
        to_send[0] = data_len + 2     # Add CRC to length

        cal_crc = self.crc_def(data)
        cal_crc = struct.pack(">H", cal_crc)
        self.log.debug("Calc CRC: %s", cal_crc)

        to_send += data
        to_send.append(cal_crc[0])
        to_send.append(cal_crc[1])

        self.log.debug("Sending %s", to_send)

        self.s.send(to_send)

    def wait_for_ack(self):
        """
        And now...we wait. For an ACK that is
        """
        d = self.receive_frame()
        if d[0] != 0x41:
            raise ReadException()

    def ecdh_exchange(self):
        """
        Function that does the ECDH exchange
        """
        own_key = ec.generate_private_key(ec.SECP192R1())
        self_public = own_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)[1:]

        self.aes_iv = secrets.token_bytes(16)

        to_send = 0xAB.to_bytes(1, 'big') + self_public + self.aes_iv

        self.send_frame(to_send, encrypted=False)
        rec = self.receive_frame(encrypted=False)

        if rec[0] != 0xE0:
            raise ReadException()

        other_public = 0x04.to_bytes(1, 'big') + rec[1:]
        other_public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP192R1(), other_public)

        self.aes_key = own_key.exchange(ec.ECDH(), other_public)

        self.cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(self.aes_iv))

    def _receive_until(self, n: int):
        """
        Internal function that receives bytes until n bytes is received
        """
        d = bytearray()
        while n > 0:
            d += self.s.recv(1)
            n -= 1
        return d
