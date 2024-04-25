""" Module for SOME/IP Packet. Includes classes and functions that manage operating with SOME/IP Packets. """

import logging
import random

logging.getLogger("scapy").setLevel(logging.DEBUG)

from scapy.all import *

#SERVICE TYPES
serviceTypes = {    'SERVICE_TYPE_PA' : 0x1000,
                    'SERVICE_TYPE_CA' : 0x2000,
                    'SERVICE_TYPE_PSU' : 0x3000,
                    'SERVICE_TYPE_CCVS' : 0x3010,
                    'SERVICE_TYPE_SNA' : 0x3020,
                    'SERVICE_TYPE_RLA' : 0x5000,
                    'SERVICE_TYPE_PAX' : 0x6000,
                    'SERVICE_TYPE_SA' : 0xC000,
                    'SERVICE_TYPE_CCVSA' : 0xC010}


#ERROR CODES
errorCodes = {  'E_OK' : 0x00,
                'E_NOT_OK' : 0x01,
                'E_UNKNOWN_SERVICE' : 0x02,
                'E_UNKNOWN_METHOD' : 0x03,
                'E_NOT_READY' : 0x04,
                'E_NOT_REACHABLE' : 0x05,
                'E_TIMEOUT' : 0x06,
                'E_WRONG_PROTOCOL_VERSION' : 0x07,
                'E_WRONG_INTERFACE_VERSION' : 0x08,
                'E_MALFORMED_MESSAGE' : 0x09,
                'E_WRONG_MESSAGE_TYPE' : 0x0a}

#MESSAGE TYPE
messageTypes = {    'REQUEST' : 0x00,
                    'REQUEST_NO_RETURN' : 0x01,
                    'NOTIFICATION' : 0x02,
                    'RESPONSE' : 0x80,
                    'ERROR' : 0x81}

#METAINFO
VERSION = 0x01
INTERFACE = 0x01

class SomeIP(Packet):
    """ Given a Packet, the SOME/IP Header information is parsed and a new Header is added. """

    global VERSION
    global INTERFACE

    name = "SOMEIP"
    fields_desc = [ XShortField("ServiceID", None),
                    XShortField("MethodID", None),
                    FieldLenField("Length", None, length_of="Payload", adjust=lambda pkt,x: x+8, fmt="I"),
                    XShortField("ClientID", None),
                    XShortField("SessionID", None),
                    XByteField("ProtocolVersion", VERSION),
                    XByteField("InterfaceVersion", INTERFACE),
                    XByteField("MessageType", None),
                    XByteField("ReturnCode", None),
		            StrLenField("Payload", "", length_from=lambda pkt:pkt.Length)]


def createPayload(methodID, msg_type):
    """ Based on the methodID value, craft a payload that can be parsed. """
    str_choices = ("Hello", "World", "xyz", "abc", "foo", "bar")
    utf8_bom = b'\xef\xbb\xbf'
    if methodID == 31000:
        data = random.randint(0, 255).to_bytes(1, byteorder='little')
        print(f"Payload: {data.hex()} for method {methodID}, message type: {msg_type}")
    elif methodID == 31001:
        data = random.randint(0, 65535).to_bytes(2, byteorder='little')
        print(f"Payload: {data.hex()} for method {methodID}, message type: {msg_type}")
    elif methodID == 31002 or methodID == 31008:
        data = random.randint(0, 4294967295).to_bytes(4, byteorder='little')
        print(f"Payload: {data.hex()} for method {methodID}, message type: {msg_type}")
    elif methodID == 31003:
        data = random.randint(0, 18446744073709551615).to_bytes(8, byteorder='little')
        print(f"Payload: {data.hex()} for method {methodID}, message type: {msg_type}")
    elif methodID == 31004:
        data = random.randint(0, 127).to_bytes(1, byteorder='little')
        print(f"Payload: {data.hex()} for method {methodID}, message type: {msg_type}")
    elif methodID == 31005:
        data = random.randint(0, 32767).to_bytes(2, byteorder='little')
        print(f"Payload: {data.hex()} for method {methodID}, message type: {msg_type}")
    elif methodID == 31006:
        data = random.randint(0, 2147483647).to_bytes(4, byteorder='little')
        print(f"Payload: {data.hex()} for method {methodID}, message type: {msg_type}")
    elif methodID == 31007:
        data = random.randint(0, 9223372036854775807).to_bytes(8, byteorder='little')
        print(f"Payload: {data.hex()} for method {methodID}, message type: {msg_type}")
    elif methodID == 31009:
        data = random.randint(0, 1).to_bytes(1, byteorder='little')
        print(f"Payload: {data.hex()} for method {methodID}, message type: {msg_type}")
    elif methodID == 31010:
        data = struct.pack("f", random.random())
        print(f"Payload: {data.hex()} for method {methodID}, message type: {msg_type}")
    elif methodID == 31011:
        data = struct.pack("d", random.random())
        print(f"Payload: {data.hex()} for method {methodID}, message type: {msg_type}")
    elif methodID == 31012:  # getString
        str_to_send = random.choice(str_choices)
        b1 = (len(str_to_send) + len(utf8_bom)).to_bytes(4, byteorder='big')
        data = b1 + utf8_bom + str_to_send.encode('utf-8')
        print(f"Payload: {data.hex()} for method {methodID}, message type: {msg_type}")
    elif methodID == 31013:  # getManyString
        if msg_type == messageTypes["REQUEST"]:
            data = random.randint(0, 4294967295).to_bytes(4, byteorder='little')
        else:
            str_to_send1 = random.choice(str_choices)
            str_to_send2 = random.choice(str_choices)
            str_to_send3 = random.choice(str_choices)
            str_to_send4 = random.choice(str_choices)
            l1 = (len(str_to_send1) + len(utf8_bom)).to_bytes(4, byteorder='big')
            l2 = (len(str_to_send2) + len(utf8_bom)).to_bytes(4, byteorder='big')
            l3 = (len(str_to_send3) + len(utf8_bom)).to_bytes(4, byteorder='big')
            l4 = (len(str_to_send4) + len(utf8_bom)).to_bytes(4, byteorder='big')
            data = (l1 + utf8_bom + str_to_send1.encode('utf-8') + l2 + utf8_bom + str_to_send2.encode('utf-8') +
                    l3 + utf8_bom + str_to_send3.encode('utf-8') + l4 + utf8_bom + str_to_send4.encode('utf-8'))
            print(f"Payload: {data.hex()} for method {methodID}, message type: {msg_type}")
    elif methodID == 31014:  # getMixed
        if msg_type == messageTypes["REQUEST"]:
            b1 = struct.pack("f", random.random())
            b2 = struct.pack("d", random.random())
            b3 = random.randint(0, 1).to_bytes(1, byteorder='little')
            data = b1 + b2 + b3
            print(f"Payload: {data.hex()} for method {methodID}, message type: {msg_type}")
        else:
            b1 = random.randint(0, 65535).to_bytes(2, byteorder='little')
            b2 = random.randint(0, 9223372036854775807).to_bytes(8, byteorder='little')
            str_to_send1 = random.choice(str_choices)
            str_to_send2 = random.choice(str_choices)
            l1 = (len(str_to_send1) + len(utf8_bom)).to_bytes(4, byteorder='big')
            l2 = (len(str_to_send2) + len(utf8_bom)).to_bytes(4, byteorder='big')
            data = b1 + b2 + l1 + utf8_bom + str_to_send1.encode('utf-8') + l2 + utf8_bom + str_to_send2.encode('utf-8')
            print(f"Payload: {data.hex()} for method {methodID}, message type: {msg_type}")
    elif methodID == 31015:  # setManyString
            str_to_send1 = random.choice(str_choices)
            str_to_send2 = random.choice(str_choices)
            str_to_send3 = random.choice(str_choices)
            l1 = (len(str_to_send1) + len(utf8_bom)).to_bytes(4, byteorder='big')
            l2 = (len(str_to_send2) + len(utf8_bom)).to_bytes(4, byteorder='big')
            l3 = (len(str_to_send3) + len(utf8_bom)).to_bytes(4, byteorder='big')
            data = (l1 + utf8_bom + str_to_send1.encode('utf-8') + l2 + utf8_bom + str_to_send2.encode('utf-8') +
                    l3 + utf8_bom + str_to_send3.encode('utf-8'))
            print(f"Payload: {data.hex()} for method {methodID}, message type: {msg_type}")
    elif methodID == 31016:  # setMixed
            str_to_send = random.choice(str_choices)
            b2 = struct.pack("f", random.random())
            b3 = random.randint(0, 1).to_bytes(1, byteorder='little')
            b4 = random.randint(0, 65535).to_bytes(2, byteorder='little')
            data = ((len(str_to_send) + len(utf8_bom)).to_bytes(4, byteorder='big') + utf8_bom +
                    str_to_send.encode('utf-8') + b2 + b3 + b4)
            print(f"Payload: {data.hex()} for method {methodID}, message type: {msg_type}")
    else:
        alpha = ("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F")
        length = random.randint(0,20)
        data = ''.join([random.choice(alpha) for _ in range(length)]).encode('utf-8')
        print(f"Payload: {data.hex()} for method {methodID}, message type: {msg_type}")

    # payload = data.hex()
    return data


def createSomeIP(SenderConfig, ReceiverConfig, MsgConfig):
    """ 
    Create a SomeIP packet based on IP/UDP 
    
    :param SenderConfig: Needed for MAC, IP and Port information of the sender.    
    :param ReceiverConfig: Needed for MAC, IP and Port information of the receiver.    
    :param MsgConfig: Content of the SOME/IP Packet incl. Header and payload.
    :returns: a SOME/IP Packet over IP/UDP    
    """    

    srcMAC = SenderConfig['mac']
    dstMAC = ReceiverConfig['mac']

    srcIP = SenderConfig['ip']
    dstIP = ReceiverConfig['ip']

    srcPort = SenderConfig['port']
    dstPort = ReceiverConfig['port']


    method = MsgConfig['method']
    msgtype = MsgConfig['type']

    pl = createPayload(method, msgtype)

    service = MsgConfig['service']
    client = MsgConfig['client'] 
    session = MsgConfig['session']
    ret = MsgConfig['ret']
    proto = MsgConfig['proto']
    iface = MsgConfig['iface']

    
    packet = Ether(src=srcMAC, dst=dstMAC)/IP(src=srcIP, dst=dstIP)/UDP(dport=dstPort, sport=srcPort)/SomeIP(ServiceID=service, MethodID=method, ClientID=client, SessionID=session, MessageType=msgtype, ReturnCode=ret, Payload=pl, ProtocolVersion=proto, InterfaceVersion=iface)

    return packet

