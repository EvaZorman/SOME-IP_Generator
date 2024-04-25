import copy
import random

from src import Msg
from src import SomeIPPacket
from src.attacks import AttackerHelper

from scapy.all import *




def fakePayload(a, msgOrig):
    """ Attack Specific Function. """
    sender = msgOrig.receiver
    receiver = msgOrig.sender
    timestamp = None

    message = {}

    message['service'] = msgOrig.message['service']
    message['method'] = msgOrig.message['method']
    message['client'] = msgOrig.message['client']
    message['session'] = msgOrig.message['session']
    message['proto'] = SomeIPPacket.VERSION
    message['iface'] = SomeIPPacket.INTERFACE
    message['type'] = msgOrig.message['type']
    message['ret'] = msgOrig.message['ret']
    message['malicious'] = True

    msg = Msg.Msg(sender, receiver, message, timestamp)

    return msg


def doAttack(curAttack, msgOrig, a, attacksSuc):
    RetVal = {}

    if a.verbose:
        print('Malformed Payload Attack')

    if (msgOrig.message['type'] == SomeIPPacket.messageTypes['RESPONSE'] or
            msgOrig.message['type'] == SomeIPPacket.messageTypes['REQUEST'] or
            msgOrig.message['type'] == SomeIPPacket.messageTypes['REQUEST_NO_RETURN']
    ):
        msg = fakePayload(a, msgOrig)

        RetVal['msg'] = msg
        RetVal['attackOngoing'] = False
        RetVal['dropMsg'] = False
        RetVal['counter'] = attacksSuc + 1

    else:
        RetVal['msg'] = None
        RetVal['attackOngoing'] = True
        RetVal['dropMsg'] = False
        RetVal['counter'] = attacksSuc

    return RetVal
