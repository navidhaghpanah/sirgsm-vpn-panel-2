#!/usr/bin/env python3
"""Unauthenticated IKEv2 INIT reachability probe. Does not establish a VPN."""
import ipaddress
import secrets
import socket
import struct
import sys

def payload(next_type,body):return struct.pack('!BBH',next_type,0,4+len(body))+body
def transform(more,kind,identifier,extra=b''):return struct.pack('!BBHBBH',3 if more else 0,0,8+len(extra),kind,0,identifier)+extra

def probe(ip,port):
    spi=secrets.token_bytes(8)
    transforms=transform(True,1,12,struct.pack('!HH',0x800e,256))+transform(True,2,5)+transform(True,3,12)+transform(False,4,14)
    proposal=struct.pack('!BBHBBBB',0,0,8+len(transforms),1,1,0,4)+transforms
    body=payload(34,proposal)+payload(40,struct.pack('!HH',14,0)+b'\x00'*255+b'\x02')+payload(0,secrets.token_bytes(32))
    packet=spi+b'\x00'*8+struct.pack('!BBBBII',33,0x20,34,8,0,28+len(body))+body
    if port==4500:packet=b'\x00'*4+packet
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        sock.settimeout(8);sock.sendto(packet,(ip,port))
        data,_=sock.recvfrom(65535)
    if port==4500:data=data[4:]
    assert data[:8]==spi and len(data)>=28,'Unexpected IKE response'
    print(f'UDP {port}: IKEv2 responder reachable ({len(data)} bytes); authentication not tested')

if __name__=='__main__':
    ip=str(ipaddress.IPv4Address(sys.argv[1]))
    for port in (500,4500):
        try:probe(ip,port)
        except socket.timeout:print(f'UDP {port}: no reply; check carrier/cloud firewall')
