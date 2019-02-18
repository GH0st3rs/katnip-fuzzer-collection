#!/usr/bin/python
from telnetlib import Telnet
import socket
import time


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


def restart_gdbserver(target_ip):
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
    gdbserver_pid = controller.send_command("ps|grep gdbserver|grep -v grep|awk '{print $1}'")
    if gdbserver_pid:
        controller.send_command('kill -9 %s' % gdbserver_pid[0])
    gdbserver_pid = ''
    while not gdbserver_pid:
        print('Find upnp')
        pid = controller.send_command("ps|grep upnp|grep -v grep|awk '{print $1}'")
        print('Run gdbserver')
        if not pid:
            print('Upnp not found! Try restart upnp server')
            upnp_sock = controller.upnp_connect()
            controller.send_command("./gdbserver_mips_old :2222 --attach $(ps|grep upnp|grep -v grep|awk '{print $1}') &")
            upnp_sock.close()
        else:
            controller.send_command("./gdbserver_mips_old :2222 --attach %s &" % pid[0])
        gdbserver_pid = controller.send_command("ps|grep gdbserver|grep -v grep|awk '{print $1}'")


if __name__ == '__main__':
    restart_gdbserver()
