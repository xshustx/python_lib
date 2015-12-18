import pyDes


class DES():
    _key = None
    _pad = None
    _padmode = None

    def setkey(self, key):
        '''
        key is string
        '''
        keyhex = bytes.fromhex(key)
        if len(keyhex) == 8:
            self._key = pyDes.des(keyhex)
        elif len(keyhex) is 16 or len(keyhex) is 24:
            self._key = pyDes.triple_des(keyhex)
        else:
            self._key = None
            return False
        return True

    def encrypt(self, data):
        '''
        data is string
        '''
        resp = self._key.encrypt(bytes.fromhex(data), self._pad, self._padmode)
        return resp.hex().upper()

    def decrypt(self, data):
        '''
        data is string
        '''
        resp = self._key.decrypt(bytes.fromhex(data), self._pad, self._padmode)
        return resp.hex().upper()

    def verifycode(self, key):
        '''
        对全零加密的校验值
        '''
        tmp = self._key  # keep
        self.setkey(key)
        mac = self.encrypt(''.zfill(16))
        self._key = tmp
        return mac

    def get_work_key(self, mkey, wkey, mac, random=None):
        '''
        mkey, 主秘钥明文， string
        wkey, 工作秘钥密文， string
        mac， 校验值，支持4、8字节，string
        '''
        tmp = self._key  # keep
        self.setkey(mkey)
        wkey = self.decrypt(wkey)
        mac1 = self.verifycode(wkey)
        # print('mac1', mac1)
        self._key = tmp
        if mac.upper() == mac1[:len(mac)]:
            if random is not None:
                tmp = self._key
                self.setkey(wkey)
                wkey = self.encrypt(random)
                self._key = tmp
            return wkey
        else:
            return False


if __name__ == "__main__":
    def test():
        mkey = '1122334455667788'
        wkey = '0000000000000000'
        des = DES()
        des.setkey(mkey)
        encode = des.encrypt(wkey)
        print('encode', encode)
        decode = des.decrypt(encode)
        print('decode', decode)
        mac = des.verifycode(wkey)
        print('mac', mac)
        wkey = des.get_work_key(mkey, encode, mac)
        print('wkey', wkey)
    test()
