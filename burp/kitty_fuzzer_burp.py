#!/usr/bin/python
import xml.etree.ElementTree as ET
import base64
import os
import time
from argparse import ArgumentParser
try:
    from BaseHTTPServer import BaseHTTPRequestHandler
    from StringIO import BytesIO
except ModuleNotFoundError:
    from http.server import BaseHTTPRequestHandler
    from io import BytesIO

from kitty.model import Static, Template, Container, String, Delimiter
from katnip.legos.http import HttpRequestLine, IntField, TextField, ContentLengthField
from katnip.legos.http import bit_length
from katnip.legos.url import DecimalNumber

from kitty.fuzzers import ServerFuzzer
from kitty.interfaces import WebInterface
from kitty.model import GraphModel
from katnip.targets.tcp import TcpTarget


def parse_args():
    parser = ArgumentParser(add_help=True)
    parser.add_argument('-s', metavar='SKIP', dest='skip', type=int, required=False, help='Skip count', default=0)
    parser.add_argument('-i', dest='input_file', required=False, help='Set burp input xml file')
    parser.add_argument('-t', dest='host', required=True, help='Target IP')
    parser.add_argument('-p', dest='port', type=int, required=True, help='Target Port')
    # parser.add_argument('-r', dest='replay', help='Path to parsed requests for replay')
    # parser.add_argument('-v', dest='verbose', action='store_true', help='Verbose', default=False)
    # parser.add_argument('-r1', dest='once_replay', action='store_true', help='Replay one package', default=False)
    # parser.add_argument('-f', dest='filtered', help='Filter message', default=None)
    return parser.parse_args()


def toJson(r, root=True):
    if root:
        return {r.tag: toJson(r, False)}
    if r.tag == 'item':
        d = {}
    else:
        d = []
    for x in r.findall('./*'):
        if x.tag == 'item':
            d.append(toJson(x, False))
        else:
            if x.tag not in ['time', 'responselength', 'mimetype', 'response', 'comment']:
                d[x.tag] = x.text
    return d


class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()


def craft_model_by_request(request):
    # Craft Kitty Model Template
    value_fields = []
    proto = request.request_version.split('/')[0]
    proto_ver = float(request.request_version.split('/')[1])
    # Append Request Line
    value_fields.append(HttpRequestLine(
        method=request.requestline.split()[0],
        uri=request.path,
        protocol=proto,
        version=proto_ver,
        fuzzable_method=True, fuzzable_uri=True,
    ))
    # Append headers
    for k, v in request.headers.items():
        if k == 'Content-Length':
            continue
        if v.isdigit():
            value_fields.append(IntField(key=k, value=int(v)))
        else:
            value_fields.append(TextField(key=k, value=v))
    # Append data if exists
    if not request.headers.get('Content-Length'):
        value_fields.append(Static(b'\r\n'))
    else:
        content_length = int(request.headers.get('Content-Length') or 0)
        value_fields.append(
            ContentLengthField(sized_field='post_data_params', value=content_length, end=True)
        )
        data = request.rfile.read(content_length)
        if request.headers.get('Content-Type') == 'application/x-www-form-urlencoded':
            value_fields.append(PostFormUrlencoded(data.decode(), name='post_data_params', fuzz_param=True))
        elif request.headers.get('Content-Type').startswith('multipart/form-data'):
            boundary = request.headers.get('Content-Type').split('boundary=')[1].encode()
            value_fields.append(PostMultipartFormData(data, boundary, name='post_data_params', fuzz_param=True))
    return Template(value_fields, name='Http_Request')


class PostMultipartFormData(Container):
    '''
    Container to fuzz the multipart/form-data params
    '''

    def __init__(self, data=b'', boundary=b'', fuzz_delims=False, fuzz_param=False, fuzz_value=True, name=None):
        self.separator = b'--%s' % boundary
        self.terminator = b'--%s--' % boundary
        multipart = self.multipart2json_parse(data)
        fields = []
        for item in multipart:
            fields += [Delimiter(self.separator, fuzzable=fuzz_delims), Static(b'\r\n')]
            inner_container_header = []
            ContentDisposition = item.get(b'header').get(b'Content-Disposition').get(b'params')
            var_name = ContentDisposition.get(b'name')
            var_value = item.get(b'value')
            for header_field in item.get(b'header'):
                header_value = item.get(b'header')[header_field].get(b'value')
                header_params = item.get(b'header')[header_field].get(b'params')
                multipart_header_name = '%s_%s' % (header_field.decode(), var_name.decode())
                inner_container_header.append(TextField(
                    key=header_field, value=header_value,
                    params=header_params, name=multipart_header_name,
                    fuzzable_key=fuzz_param, fuzzable_value=fuzz_value
                ))
            inner_container_header.append(Static(b'\r\n'))
            fields.append(Container(fields=inner_container_header, name='%s_header' % var_name))
            # Append multipart param value
            if var_value.isdigit():
                fields.append(DecimalNumber(
                    name="multipart_value_%s" % var_name.decode(),
                    num_bits=bit_length(int(var_value)),
                    value=int(var_value), signed=True
                ))
            else:
                fields.append(String(var_value))
            fields.append(Static(b'\r\n'))
        # Append terminator boundary
        fields += [
            Delimiter(self.terminator, fuzzable=fuzz_delims),
            Static(b'\r\n')
        ]
        super(PostMultipartFormData, self).__init__(name=name, fields=fields, fuzzable=fuzz_value)

    def multipart2json_parse(self, data):
        '''
        Parse multipart/form-data body to json
        Return [{
            'header': {
                'Content-Disposition': {
                    'value': 'form-data',
                    'params': {'name': 'sid'},
                }
            },
            'value': '3447a86f3a798554'
        }, ]
        '''
        multipart = []
        d = data.split(self.terminator)[0].split(self.separator)
        for item in d:
            if not item.strip():
                continue
            header = {}
            params, value = item.split(b'\r\n\r\n')
            headers = params.strip().split(b'\r\n')
            for h in headers:
                header_name, header_value = h.split(b'; ')[0].split(b':')
                header_params = h.split(b'; ')[1:]
                header_value_tuple = {b'value': header_value.strip(), b'params': {}}
                for h_p in header_params:
                    param_name, param_value = h_p.split(b'=')
                    header_value_tuple[b'params'].update({param_name: param_value.replace(b'"', b'')})
                header.update({header_name.strip(): header_value_tuple})
            multipart.append({b'header': header, b'value': value.split(b'\r\n', -1)[0]})
        return multipart


class PostFormUrlencoded(Container):
    '''
    Container to fuzz the params of the POST data
    '''

    def __init__(self, data='', fuzz_delims=False, fuzz_param=False, fuzz_value=True, fuzzable=True, name=None):
        '''
        :param data: data string (default: '')
        :param fuzz_delims: should fuzz the delimiters (default: False)
        :param name: name of container (default: None)
        :param fuzzable: should fuzz the container (default: True)
        '''
        fields = []
        for i, part in enumerate(data.split('&')):
            part = part.split('=')
            if len(fields) >= 1:
                fields.append(Delimiter(name='search_delim_%d' % i, value='&', fuzzable=fuzz_delims))
            fields.append(Container(name='param_%s' % part[0], fields=[
                String(name='search_%d_key' % i, value=part[0], fuzzable=fuzz_param),
                Delimiter(value='=', fuzzable=fuzz_delims),
                String(name='search_%d_value' % i, value=part[1], fuzzable=fuzz_value)
            ]))
        super(PostFormUrlencoded, self).__init__(name=name, fields=fields, fuzzable=fuzzable)


def fuzzing(host, port, template):
    # Define target
    target = TcpTarget('HTTP', host, int(port), timeout=1)
    target.set_expect_response(True)
    # target.add_monitor(monitor)
    # Define model
    model = GraphModel()
    model.connect(template)
    # Define fuzzer
    fuzzer = ServerFuzzer()
    fuzzer.set_interface(WebInterface(port=4445))
    fuzzer.set_delay_between_tests(0.2)
    # Run fuzzer
    session_name = '%s.sqlite' % time.ctime().replace(' ', '_')
    sessions_dbs = os.path.join('/tmp', 'sessions', session_name)
    fuzzer.set_session_file(sessions_dbs)
    fuzzer.set_store_all_reports('reports')
    fuzzer.set_target(target)
    fuzzer.set_model(model)
    fuzzer.start()
    fuzzer.stop()


def reinit():
    os.system('rm -rf /tmp/sessions reports kittylogs *.log')
    os.mkdir('/tmp/sessions')
    os.mkdir('reports')


def main():
    args = parse_args()
    file = args.input_file
    root = ET.fromstring(open(file).read())
    items = toJson(root)
    i = 0
    reinit()
    for item in items['items']:
        raw_request = base64.b64decode(item['request'])
        request = HTTPRequest(raw_request)
        model = craft_model_by_request(request)
        if raw_request != model.render().tobytes():
            open('/tmp/original', 'wb').write(raw_request)
            open('/tmp/model', 'wb').write(model.render().tobytes())
            print('Request are different')
            os.system('diff --color=auto -u /tmp/original /tmp/model')
        i += 1
        for x in range(args.skip):
            model.mutate()
        fuzzing(args.host, args.port, model)


if __name__ == '__main__':
    main()
