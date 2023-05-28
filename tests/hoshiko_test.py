from hoshi import Hoshi
from hoshi.packet import Packet
from hoshi.rule import Rule
import unittest
import uuid


class HoshikoIDSTest(unittest.TestCase):
    def test_rule_detected(self):
        log_message = f'Detected {uuid.uuid4()}'
        rules = [Rule(
            'log',
            'any',
            'any',
            'any',
            'any',
            'any',
            log_message
        )]
        packet = Packet(
            '192.168.1.1',
            0,
            '192.168.1.2',
            0,
            'ICMP',
            'TCP',
            'IP'
        )
        hoshi = Hoshi(rules)
        return_value = hoshi._check_packet(packet)
        assert return_value.message == log_message

    def test_rule_not_detected(self):
        log_message = f'Detected {uuid.uuid4()}'
        rules = [Rule(
            'print',
            'DNS',
            '192.168.97.1',
            'any',
            'any',
            'any',
            log_message
        )]
        packet = Packet(
            '192.168.1.1',
            0,
            '192.168.1.2',
            0,
            'ICMP',
            'TCP',
            'IP'
        )
        hoshi = Hoshi(rules)
        return_value = hoshi._check_packet(packet)
        assert return_value is None

    def test_negation_rule_detected(self):
        log_message = f'Detected {uuid.uuid4()}'
        rules = [Rule(
            'log',
            'any',
            '!192.168.1.2',
            'any',
            'any',
            'any',
            log_message
        )]
        packet = Packet(
            '192.168.1.1',
            0,
            '192.168.1.2',
            0,
            'ICMP',
            'TCP',
            'IP'
        )
        hoshi = Hoshi(rules)
        return_value = hoshi._check_packet(packet)
        assert return_value.message == log_message

    def test_negation_rule_not_detected(self):
        log_message = f'Detected {uuid.uuid4()}'
        rules = [Rule(
            'log',
            'any',
            '!192.168.1.1',
            'any',
            'any',
            'any',
            log_message
        )]
        packet = Packet(
            '192.168.1.1',
            0,
            '192.168.1.2',
            0,
            'ICMP',
            'TCP',
            'IP'
        )
        hoshi = Hoshi(rules)
        return_value = hoshi._check_packet(packet)
        assert return_value is None
