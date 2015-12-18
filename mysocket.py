import socket


class SOCKET():
    ip = None
    port = None
    socket = None

    def connect(self):
        '''
        return True or False
        '''
        if self.ip is None or self.port is None:
            return False
        self.socket = socket.socket()
        self.socket.connect((self.ip, self.port))
        return True

    def recv(self, maxlen):
        '''
        return string
        '''
        respond = self.socket.recv(maxlen)
        return respond.hex()

    def send(self, data):
        '''
        input data is string
        '''
        self.socket.send(bytes.fromhex(data))
        return



