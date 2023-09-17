#!/usr/bin/python3 -u

# @file message
# @author Purdue eCTF Team
# @brief message class for host tools
# @date 2023
#
# This file contains the message class for host tools
#
# @copyright Copyright (c) 2023 Purdue eCTF Team

import struct
import socket

# @class Message
# @brief A class to represent a message sent between the host and the board
# @details This class is used to represent a message sent between the host and the board. It contains
# the header, length, and data of the message. It also contains static methods to send and receive
# messages.
class Message:
    ## Fob -> Car Headers: To Unlock
    # dups
    UNLOCK_HDR = 0x55
    ARRAY_HDR = 0x55
    # others
    UNLOCK_RES_HDR = 0x52
    START_HDR = 0x53
    ## Car -> Fob Headers: To Unlock
    CHALLENGE_HDR = 0x43

    ## Host <-> Car/Fob Headers: For Acknowledgements
    ACK_HDR = 0x41

    ## Host -> Fob Headers: To pair Unpaired Fob
    HOST_PAIR_HDR = 0x50

    ## Paired Fob -> Unpaired Fob Headers: To pair Unpaired Fob
    BOARD_PAIR_HDR = 0x60

    ## Host -> Fob & Car -> Host Headers: For Feature Enable
    HOST_FEATURE_HDR = 0x46

    ## Car/Fob -> Host Headers: To print Debug Messages
    HOST_MESSAGE_HDR = 0x4D
    
    ## Message buffer size
    MESSAGE_BUFFER_MAX = 78

    HEADERS = [
        UNLOCK_HDR,
        UNLOCK_RES_HDR,
        CHALLENGE_HDR,
        START_HDR,
        ACK_HDR,
        HOST_PAIR_HDR,
        HOST_FEATURE_HDR,
        HOST_MESSAGE_HDR,
        BOARD_PAIR_HDR
    ]

    ACK_SUCCESS = 0x1
    ACK_FAILURE = 0x0

    # @brief Constructor for the Message class
    # @param header The header of the message
    # @param data The data of the message
    def __init__(self, header, data):
        self.header = header
        self.data = data
        self.length = len(data)

    # @brief String representation of the Message class
    # @return A string representation of the Message class
    def __str__(self):
        return f"Header: {self.header}, Length: {self.length}, Data: {self.data}"

    # @brief Prints the message
    # @details Prints the message in a human readable format
    def print(self):
        if self.header == Message.ARRAY_HDR or self.header == Message.HOST_MESSAGE_HDR:
            print("[<-]", end=" ")
        if self.header == Message.ARRAY_HDR:
            for i in range(0, len(self.data)):
                print("{:02x}".format(self.data[i]), end="")
            print("")
        else:
            if len(self.data) > 0:
                if self.data[-1] == 10:
                    print(self.data[:-1].decode())
                else:
                    print(self.data.decode())

    # @brief Sends the message
    # @param sock The socket to send the message on
    def send(self, sock):
        sock.send(struct.pack("B", self.header))
        sock.send(struct.pack("B", self.length))
        sock.send(self.data)
        if self.length < Message.MESSAGE_BUFFER_MAX:
            sock.send(b"\x00" * (Message.MESSAGE_BUFFER_MAX - self.length))

    # @brief Checks if the header is valid
    # @param header The header to check
    # @return True if the header is valid, False otherwise
    @staticmethod
    def is_valid_header(header):
        return header in Message.HEADERS

# @brief Gets a message from the socket
# @param sock The socket to get the message from
# @return The message received from the socket
def get_message(sock: socket.socket):
    header = sock.recv(1)
    if len(header) == 0:
        return None
    header = struct.unpack("B", header)[0]
    if not Message.is_valid_header(header):
        return None
    length = struct.unpack("B", sock.recv(1))[0]
    data = sock.recv(length)
    while len(data) != length:
        data += sock.recv(length - len(data))
    padding = sock.recv(Message.MESSAGE_BUFFER_MAX - length)
    while len(padding) != Message.MESSAGE_BUFFER_MAX - length:
        padding += sock.recv(Message.MESSAGE_BUFFER_MAX - length - len(padding))
    return Message(header, data)
