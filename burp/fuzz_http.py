#!/usr/bin/python
import socket
import os
import xml.etree.ElementTree as ET
from argparse import ArgumentParser
import base64
import time
import hashlib
import tempfile


def parse_args():
    parser = ArgumentParser(add_help=True)
    parser.add_argument('-s', metavar='SKIP', dest='skip', type=int, required=False, help='Skip count', default=0)
    parser.add_argument('-i', dest='input_file', required=False, help='Set burp input xml file')
    parser.add_argument('-t', dest='host', required=True, help='Target IP')
    parser.add_argument('-p', dest='port', type=int, required=True, help='Target Port')
    parser.add_argument('-r', dest='replay', help='Path to parsed requests for replay')
    parser.add_argument('-v', dest='verbose', action='store_true', help='Verbose', default=False)
    parser.add_argument('-r1', dest='once_replay', action='store_true', help='Replay one package', default=False)
    parser.add_argument('-f', dest='filtered', help='Filter message', default=None)
    return parser.parse_args()


def unique(file):
    if not hasattr(unique, 'hashes'):
        setattr(unique, 'hashes', [])
    d = open(file, 'rb').read()
    h = hashlib.md5(d).hexdigest()
    if h in unique.hashes:
        os.remove(file)
    else:
        unique.hashes.append(h)


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


def parse_input(dest_dir, file, filtered=None):
    root = ET.fromstring(open(file).read())
    items = toJson(root)
    i = 0
    for item in items['items']:
        request = base64.b64decode(item['request'])
        if filtered:
            if filtered.encode() not in request:
                continue
        open('/tmp/fuzz_test', 'wb').write(request)
        os.system('cat /tmp/fuzz_test|radamsa -n 5000 -o %s/fuzz_%d_%%n.txt' % (dest_dir, i))
        i += 1
    print('Delete dublicates')
    full_path_map = map(lambda x: os.path.join(dest_dir, x), os.listdir(dest_dir))
    list(map(unique, full_path_map))


def send(host, port, data):
    s = socket.socket()
    s.connect((host, port))
    s.settimeout(1)
    try:
        s.send(data)
        output = s.recv(4096)
        if b'503 Service Unavailable' in output:
            time.sleep(10)
    except socket.timeout:
        output = b'{!} ERROR [Socket Timeout]'
    except ConnectionResetError:
        output = b'{!} ERROR [Connection Reset]'
    s.close()
    return output.strip()


def main():
    args = parse_args()
    host = args.host
    port = args.port
    if args.input_file:
        dest_dir = tempfile.mkdtemp()
        print('Created input dir: %s' % dest_dir)
        parse_input(dest_dir, args.input_file, args.filtered)
    # start fuzzing
    if args.replay:
        dest_dir = args.replay
    count = 0
    for item in filter(lambda x: x.startswith('fuzz'), os.listdir(dest_dir)):
        count += 1
        if args.skip > count:
            continue
        data = open(os.path.join(dest_dir, item), 'rb').read()
        if args.verbose:
            print('\n%s\n' % ('+' * 80))
            print(data)
            print('\n%s\n' % ('+' * 80))
        print('\n\nCount: %d\n%s\n\n' % (count, send(host, port, data)))
        if args.once_replay:
            break


if __name__ == '__main__':
    main()
