#!/usr/bin/python3

# 2021 Collegiate eCTF
# SCEWL Security Server
# Ben Janis
#
# (c) 2021 The MITRE Corporation
#
# This source file is part of an example system for MITRE's 2021 Embedded System CTF (eCTF).
# This code is being provided only for educational purposes for the 2021 MITRE eCTF competition,
# and may not meet MITRE standards for quality. Use this code at your own risk!

import socket
import select
import struct
import argparse
import logging
import random
import sys
import os
from typing import NamedTuple


SSS_IP = 'localhost'
SSS_ID = 1

# mirroring scewl enum at scewl.c:4
ALREADY, REG, DEREG = -1, 0, 1

logging.basicConfig(level=logging.DEBUG)

Device = NamedTuple('Device', [('id', int), ('status', int), ('csock', socket.socket)])

KEY = os.urandom(16)

class SSS:
    def __init__(self, sockf, start_id, end_id):
        # Make sure the socket does not already exist
        try:
            os.unlink(sockf)
        except OSError:
            if os.path.exists(sockf):
                raise

        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(sockf)
        self.sock.listen(10)
        self.devs = {}
        self.start_id = int(start_id)
        self.end_id = int(end_id)
    
    @staticmethod
    def sock_ready(sock, op='r'):
        rready, wready, _ = select.select([sock], [sock], [], 0)
        return rready if op == 'r' else wready

    def handle_transaction(self, csock: socket.SocketType):
        logging.debug('handling transaction')
        data = b''
        reg_packet_len = 32 #need to match controller.c/.h 's definition
        while len(data) < reg_packet_len:
            recvd = csock.recv(reg_packet_len - len(data))
            data += recvd

            # check for closed connection
            if not recvd:
                raise ConnectionResetError
        logging.debug(f'Received buffer: {repr(data)}')
#        _, _, _, _, dev_id, op = struct.unpack('<HHHHHH', data)
        _, _, _, _, dev_id, op, reg_num, _ = struct.unpack('<HHHHHHL16s', data)

#TODO: check reg_num, need to make a list of vaild reg_num when making a deployment
#      then check if the given number is within the allowed list

        valid = True
        
        numlist = open('/secrets/reg_num_list','r').read()
        numlist = [list(map(int,i.split(','))) for i in numlist.split('|')[1:]]

        reg_nums = {}
        for i in numlist:
            reg_nums[i[0]] = i[1]

        if int(dev_id) < self.start_id or int(dev_id) >= self.end_id:
            logging.info(f'{dev_id}:invaild sed')
            valid = False

        elif reg_num != reg_nums.get(dev_id):
            logging.info(f'{dev_id}:invaild sed')
            valid = False


        # requesting repeat transaction
        elif dev_id in self.devs and self.devs[dev_id] == op:
            resp_op = ALREADY
            logging.info(f'{dev_id}:already {"Registered" if op == REG else "Deregistered"}')
        # record transaction
        else:
            self.devs[dev_id] = Device(dev_id, op, csock)
            resp_op = op
            logging.info(f'{dev_id}:{"Registered" if op == REG else "Deregistered"}')

        # send response
        if valid:
            resp = struct.pack('<2sHHHHhL16s', b'SC', dev_id, SSS_ID, 4+4+16, dev_id, resp_op, 0, KEY)
        else:
            resp = struct.pack('<2sHHHHhL16s', b'SC', dev_id, SSS_ID, 4, dev_id, resp_op, 0, b'a'*16)

        logging.debug(f'Sending response {repr(data)}')
        csock.send(resp)

    def start(self):
        unattributed_socks = set()

        # serve forever
        while True:
            # check for new client
            if self.sock_ready(self.sock):
                csock, _ = self.sock.accept()
                logging.info(f':New connection')
                unattributed_socks.add(csock)
                continue

            # check pool of unattributed sockets first
            for csock in unattributed_socks:
                try:
                    if self.sock_ready(csock):
                        self.handle_transaction(csock)
                        unattributed_socks.remove(csock)
                        break
                except (ConnectionResetError, BrokenPipeError):
                    logging.info(':Connection closed')
                    unattributed_socks.remove(csock)
                    csock.close()
                    break
            
            # check pool of attributed sockets first
            old_ids = []
            for dev in self.devs.values():
                if dev.csock and self.sock_ready(dev.csock):
                    try:
                        self.handle_transaction(dev.csock)
                    except (ConnectionResetError, BrokenPipeError):
                        logging.info(f'{dev.id}:Connection closed')
                        dev.csock.close()
                        old_ids.append(dev.id)
            
            for dev_id in old_ids:
                del self.devs[dev_id]


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('sockf', help='Path to socket to bind the SSS to')
    parser.add_argument('start_id', help='The start of the SCEWL_ID range')
    parser.add_argument('end_id', help='The end of the SCEWL_ID range')
    return parser.parse_args()


def main():
    args = parse_args()
    # map of SCEWL IDs to statuses
    sss = SSS(args.sockf, args.start_id, args.end_id)

    sss.start()


if __name__ == '__main__':
    main()
