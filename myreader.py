
# from smartcard.Exceptions import NoCardException
from smartcard.System import readers


class READER:
    readerhandle = None
    name = None
    debug = False
    cmd = None
    resp = list()

    def find(self, index):
        name = None
        if len(readers()) > index:
            name = readers()[index].name
            if self.debug:
                print('Find dev: ' + name)
        else:
            if self.debug:
                print('Can not find reader!')
        return name

    def connect(self, index):
        '''
        成功返回atr
        失败返回None
        '''
        name = self.find(index)
        if name is None:
            return None
        self.name = name
        self.readerhandle = readers()[index].createConnection()
        self.readerhandle.connect()
        ATR = self.readerhandle.getATR()
        return ATR

    def reset(self):
        '''
        设备复位，返回ATR
        失败返回None
        '''
        if self.readerhandle is None:
            return None
        ATR = self.readerhandle.getATR()
        resp = bytes()
        for i in ATR:
            resp += i.to_bytes(1, 'big')
        ATR = resp.hex().upper()
        return ATR

    def _transmit(self, apdustr):  # str 'f0c3000000'
        '''
        输入字符串: 'f0c300000101'
        返回字符串元组：('01', '9000')
        '''
        if self.readerhandle is None:
            return None
        apdulist = []
        for b in bytes.fromhex(apdustr):
            apdulist.append(b)
        data, sw1, sw2, = self.readerhandle.transmit(apdulist)
        # print("data", data)
        resp = bytes()
        for i in data:
            resp += i.to_bytes(1, 'big')
        sw = sw1.to_bytes(1, 'big') + sw2.to_bytes(1, 'big')
        return (resp.hex().upper(), sw.hex().upper())

    def _showcmd(self, cmd):
        cmd = cmd.upper()
        if cmd[8:10] == '00' and len(cmd) > 14:
            print('Send-> ', cmd[:4], cmd[4:8], cmd[8:14], cmd[14:])
        else:
            print('Send-> ', cmd[:4], cmd[4:8], cmd[8:10], cmd[10:])

    def _shworesp(self, resp):
        if resp[0] == '':
            print('Recv<- ', resp[1], '\n')
        else:
            print('Recv<- ', resp[0] + ' ' + resp[1], '\n')

    def exchange(self, cmd):
        self.cmd = cmd
        self.resp.clear()
        self.resp += self._transmit(cmd)
        if self.debug is False:
            return
        self._showcmd(self.cmd)
        self._shworesp(self.resp)

if __name__ == '__main__':
    def test():
        apduCmdGetPn = 'fe01010300'
        mPos = READER()
        ATR = mPos.connect(0)
        if ATR is None:
            print('None devece')
            return
        respond = mPos.transmit(apduCmdGetPn)
        print('respond', respond)
        print('reset atr', mPos.reset())
        print('pos name', mPos.name)

    test()
