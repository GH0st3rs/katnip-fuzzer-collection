#!/usr/bin/python
import socket
from argparse import ArgumentParser
from report_parser import show_report_by_id


def parse_args():
    parser = ArgumentParser(description='Replay payload sender')
    parser.add_argument('-s', dest='session_path', required=True, help='Path to sessions')
    parser.add_argument('-i', dest='id', required=True, help='Report id for show')
    parser.add_argument('-t', dest='target', required=True, help='Target address')
    parser.add_argument('-p', dest='port', required=True, type=int, help='Target port')
    return parser.parse_args()


def resend(host, port, data):
    sock = socket.socket()
    sock.connect((host, port))
    print(data)
    sock.send(data)
    data = sock.recv(4096)
    sock.close()
    return data


def main():
    args = parse_args()
    report = show_report_by_id(args.session_path, args.id)
    print(resend(args.target, args.port, report['payload']['raw']))


if __name__ == '__main__':
    main()
