#!/usr/bin/python
from telnetlib import Telnet
import socket
import time
import sys


class TelnetController(object):
    def __init__(self, host, login, password):
        self.target = host
        self.login = login
        self.password = password
        self.telnet = None
        self.is_auth = False

    def upnp_connect(self):
        s = socket.socket()
        s.connect((self.target, 37215))
        return s

    def send_command(self, cmd):
        if not self.is_auth:
            self.auth()
        time.sleep(0.5)
        self.telnet.write(b'%s\n' % cmd.encode())
        data = self.telnet.read_until(b'# ').decode()
        return data.splitlines()[1:-1]

    def auth(self):
        if not self.telnet:
            self.connect()
        print('Try auth')
        self.telnet.read_until(b'Login: ')
        self.telnet.write(('%s\n' % self.login).encode())
        self.telnet.read_until(b'Password: ')
        self.telnet.write(('%s\n' % self.password).encode())
        if self.telnet.read_until(b'ATP>'):
            self.is_auth = True
            self.telnet.write(b'sh\n')

    def connect(self):
        self.telnet = Telnet(self.target, timeout=1)


def restart_gdbserver(target_ip, process_name='upnp', callback=None):
    pid_command = "ps|grep %s|grep -v grep|awk '{print $1}'"
    print('Try connect to telnet')
    controller = TelnetController(target_ip, login='!!Huawei', password='@HuaweiHgw')
    time.sleep(1)
    print('Goto shell')
    controller.send_command('su')
    controller.send_command('cd /tmp')
    print('Check gdbserver if exists')
    answer = controller.send_command('ls gdbserver*')
    if 'No such file or directory' in answer[0]:
        print('gdbserver not found')
        exit(-1)
    print('Check previous gdbserver')
    gdbserver_pid = controller.send_command(pid_command % 'gdbserver')
    if gdbserver_pid:
        controller.send_command('kill -9 %s' % gdbserver_pid[0])
    gdbserver_pid = ''
    while not gdbserver_pid:
        print('Find %s' % process_name)
        pid = controller.send_command(pid_command % process_name)
        print('Run gdbserver')
        if not pid:
            print('%s not found! Try restart' % process_name)
            callback()
        controller.send_command("./gdbserver_mips_old :2222 --attach $(%s) &" % (pid_command % process_name))
        gdbserver_pid = controller.send_command(pid_command % 'gdbserver')


if __name__ == '__main__':
    if len(sys.argv) >= 3:
        restart_gdbserver(sys.argv[1], sys.argv[2])
