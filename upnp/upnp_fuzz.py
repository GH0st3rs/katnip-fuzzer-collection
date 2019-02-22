#!/usr/bin/python
import socket
import os
from xml.dom import minidom
import time
import signal
import requests
from argparse import ArgumentParser

from kitty.fuzzers import ServerFuzzer
from kitty.interfaces import WebInterface
from kitty.model import GraphModel
from kitty.model.low_level import Container, Static, String, Template

from katnip.targets.tcp import TcpTarget
from katnip.monitors.gdbserver import GdbServerMonitor
from katnip.legos.http import TextField, IntField, HttpRequestLine
from katnip.legos.xml import XmlAttribute, XmlElement
from katnip.legos.url import urlparse

# from legos_xml import XmlNode, xmlTextAttribute, xmlAttribute
from telnet import restart_gdbserver


def parse_args():
    parser = ArgumentParser('UPNP fuzzer')
    parser.add_argument('-t', dest='target_ip', help='Target ip or nothing for autodetect', default='239.255.255.250')
    return parser.parse_args()


def send_ssdp(ip):
    ip = '239.255.255.250' if not ip else ip
    msg = \
        'M-SEARCH * HTTP/1.1\r\n' \
        'HOST:%s:1900\r\n' \
        'ST:upnp:rootdevice\r\n' \
        'MX:2\r\n' \
        'MAN:"ssdp:discover"\r\n' \
        '\r\n' % ip
    # Set up UDP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.settimeout(2)
    s.sendto(msg.encode(), (ip, 1900))
    data = None
    try:
        while True:
            data, _ = s.recvfrom(65507)
    except socket.timeout:
        pass
    # parse response
    if not data:
        return None
    headers = dict(map(lambda x: (x.partition(':')[0], x.partition(':')[2].strip()), data.decode().split('\r\n')[1:][:-2]))
    return headers.get('LOCATION')


class SCPD():
    def get_actions(self, xmldoc):
        itemlist = xmldoc.getElementsByTagName('action')
        actions = {}
        for s in itemlist:
            func_name = s.getElementsByTagName('name')[0].firstChild.wholeText
            arguments = []
            for b in s.getElementsByTagName('argument'):
                arg_name = b.getElementsByTagName('name')[0].firstChild.wholeText
                arg_direction = b.getElementsByTagName('direction')[0].firstChild.wholeText
                relatedStateVariable = b.getElementsByTagName('relatedStateVariable')[0].firstChild.wholeText
                arguments.append({
                    'name': arg_name,
                    'direction': arg_direction,
                    'rsv': relatedStateVariable,
                })
            actions[func_name] = arguments
        return actions

    def parse(self, url):
        services = []
        parsed_url = urlparse(url)
        upnp_dev = requests.get(url).text
        xmldoc = minidom.parseString(upnp_dev)
        services_xml = xmldoc.getElementsByTagName('service')
        if services_xml:
            for service in services_xml:
                serviceType = service.getElementsByTagName('serviceType')[0].firstChild.wholeText
                controlURL = service.getElementsByTagName('controlURL')[0].firstChild.wholeText
                SCPDURL = service.getElementsByTagName('SCPDURL')[0].firstChild.wholeText
                services.append({
                    'controlURL': controlURL,
                    'serviceType': serviceType,
                    'actions': self.parse('%s://%s%s' % (parsed_url.scheme, parsed_url.netloc, SCPDURL))
                })
            return services
        return self.get_actions(xmldoc)


# def createPayload(service, function, arguments):
#     # container for created nodes
#     action_param_nodes = []
#     for k in filter(lambda x: x.get('direction') != 'out', arguments):
#         action_param_nodes.append(XmlNode(tag=k['name'], value='Value'))
#     # create the Function element and set its attribute
#     fn = XmlNode(
#         tag='u:%s' % function,
#         value=action_param_nodes,
#         attributes=[
#             xmlAttribute('xmlns:u', [
#                 Static('urn:schemas-upnp-org:service:'), String(service), Static(':1')
#             ])
#         ],
#     )
#     # create the Body element
#     body = XmlNode(tag='s:Body', value=fn)
#     # create the Envelope element and set its attributes
#     envelope = XmlNode(
#         tag='s:Envelope',
#         value=body,
#         attributes=[
#             xmlTextAttribute('xmlns:s', 'http://schemas.xmlsoap.org/soap/envelope/'),
#             xmlTextAttribute('s:encodingStyle', 'http://schemas.xmlsoap.org/soap/encoding/'),
#         ],
#     )
#     # Create UPNP body
#     return Container(name='upnp_body', fields=[envelope])


def createPayload(service, function, arguments):
    # container for created nodes
    action_param_nodes = []
    for k in filter(lambda x: x.get('direction') != 'out', arguments):
        action_param_nodes.append(XmlElement(name=k['name'], element_name=k['name'], content='Value'))
    # function attribute
    u = [Static('urn:schemas-upnp-org:service:'), String(service), Static(':1')]
    # create the Function element and set its attribute
    function_element = [XmlElement(
        name=function,
        element_name='u:%s' % function,
        attributes=[XmlAttribute(name='attr_u', attribute='xmlns:u', value=u)],
        content=action_param_nodes
    )]
    # create the Body element
    body = [XmlElement(name='Body', element_name='s:Body', content=function_element)]
    # create the Envelope element and set its attributes
    envelope = XmlElement(
        name='Envelope',
        element_name='s:Envelope',
        content=body,
        attributes=[
            XmlAttribute(name='attr_s', attribute='xmlns:s', value='http://schemas.xmlsoap.org/soap/envelope/'),
            XmlAttribute(name='attr_encodingStyle', attribute='s:encodingStyle', value='http://schemas.xmlsoap.org/soap/encoding/'),
        ],
    )
    return Template(envelope, name='upnp_body')


def createHeaders(url, host, action):
    data = Container(name='http_header', fields=[
        HttpRequestLine(['POST'], url),
        TextField('Host', host),
        TextField('User-Agent', 'python-requests/2.21.0'),
        TextField('Content-Type', 'text/xml'),
        TextField('SOAPAction', action),
        IntField('Content-Length', 5000, end=True)
    ])
    return data


def fuzzing(host, port, template):
    # Define target
    monitor = GdbServerMonitor(
        name='GdbServerMonitor', gdb_path='gdb-multiarch',
        host=host, port=2222,
        signals=[signal.SIGSEGV, signal.SIGILL, signal.SIGKILL, signal.SIGTERM]
    )
    target = TcpTarget('upnp', host, int(port), timeout=1)
    target.set_expect_response(True)
    target.add_monitor(monitor)
    # Define model
    model = GraphModel()
    model.connect(template)
    # Define fuzzer
    fuzzer = ServerFuzzer()
    fuzzer.set_interface(WebInterface(port=4445))
    fuzzer.set_delay_between_tests(0.2)
    # Run fuzzer
    fuzzer.set_session_file('sessions/%s.sqlite' % time.ctime().replace(' ', '_'))
    fuzzer.set_store_all_reports('reports')
    fuzzer.set_target(target)
    fuzzer.set_model(model)
    fuzzer.start()
    fuzzer.stop()


def reinit():
    os.system('rm -rf sessions reports kittylogs *.log')
    os.mkdir('sessions')
    os.mkdir('reports')


def main():
    args = parse_args()
    location_url = send_ssdp(args.target_ip)
    if location_url is not None:
        UPNP = SCPD().parse(location_url)
    else:
        logger('Router not found')
        exit(-1)
    reinit()
    print('Router found: %s' % location_url)
    parsed_url = urlparse(location_url)
    host, port = parsed_url.netloc.split(':')
    # Loop by templates
    for name, template in generate_fuzz_templates(parsed_url, UPNP):
        # input('Wait connect to GdbServerMonitor')
        restart_gdbserver(host)
        logger('Start fuzzing: %s' % name)
        fuzzing(host, port, template)
        return None


def generate_fuzz_templates(parsed_url, upnp):
    for upnp_srv in upnp:
        service = upnp_srv['serviceType'].split(':')[-2]
        for function in upnp_srv['actions']:
            arguments = upnp_srv['actions'][function]
            upnp_payload = createPayload(service, function, arguments)
            headers = createHeaders(upnp_srv['controlURL'], parsed_url.netloc, upnp_srv['serviceType'])
            test_string = '{} {} {} {} {} {}'.format(service, function, arguments, upnp_srv['controlURL'], parsed_url.netloc, upnp_srv['serviceType'])
            template = Container(name='upnp_request', fields=[headers, upnp_payload])
            yield (test_string, template)


def logger(data):
    print(data)
    open('fuzzer_log.log', 'a+').write(data + '\n')


if __name__ == '__main__':
    main()
