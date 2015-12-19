from mylib import mydes


def xor(data0, data1):
        '''
        data0 is hex string
        data1 is hex string
        len(data0) == len(data1)
        '''
        data0 = bytes.fromhex(data0)
        data1 = bytes.fromhex(data1)
        count = 0
        xordata = b''
        for x in data0:
            # print(x, data1[count])
            xordata += (x ^ data1[count]).to_bytes(1, 'big')
            count += 1
        return xordata.hex().upper()


def pinblock(track2, pin, pik):
    '''
    track2: pan or track2, hex string
    pin:    pin, string
    pik:    pin key
    '''

    # format pan
    index = track2.find('D')
    if index != -1:
        pan = track2[:index]
    else:
        pan = track2
    pan = '0000' + pan[-13:-1]
    # print(pan)

    # format pin
    pin = str(len(pin)).zfill(2) + pin
    pin = pin.ljust(16, 'f')
    # print(pin)

    # do xor
    data = xor(pan, pin)
    # print(data)

    # do encrypt
    des = mydes.DES()
    des.setkey(pik)
    data = des.encrypt(data)
    return data


def rpinblock(pinblock, track2, pik):
    '''
    pinblock:    pinblock, string
    track2: pan or track2, string
    pik:    pin key, string
    '''

    # format pan
    index = track2.find('D')
    if index != -1:
        pan = track2[:index]
    else:
        pan = track2
    pan = '0000' + pan[-13:-1]
    # print(pan)

    des = mydes.DES()
    des.setkey(pik)
    data = des.decrypt(pinblock)

    data = xor(data, pan)
    # find pin
    lenth = int(data[:2])
    data = data[2:lenth + 2]

    return data


def mac_calc(data, key, type):
    def datafill(data):
        '''
        data is string
        fill to X16
        '''
        while len(data) % 16:
            data += '0'
        return data

    def doxor(data):
        '''
        data is X16 string
        '''
        offset = 0
        data0 = data[offset:offset+16]
        # print(data0)
        offset += 16
        while offset < len(data):
            data1 = data[offset:offset+16]
            # print(data1)
            offset += 16
            data0 = xor(data0, data1)
        return data0.upper()

    def unio_mac(data, key):
        des = mydes.DES()
        des.setkey(key)
        txt = datafill(data)
        txt = doxor(txt)
        txt = txt.encode().hex()
        mac = des.encrypt(txt[:16]) + txt[16:]
        mac = doxor(mac)
        mac = des.encrypt(mac)
        return mac

    def custom_mac(data, key):
        des = mydes.DES()
        des.setkey(key)
        txt = datafill(data)
        txt = doxor(txt)
        mac = des.encrypt(txt)
        return mac

    def x919_mac(data, key):
        des = mydes.DES()
        des.setkey(key[:16])
        offset = 0
        data0 = data[offset:offset+16]
        # print(data0)
        offset += 16
        data0 = des.encrypt(data0)
        while offset < len(data):
            data1 = data[offset:offset+16]
            # print(data1)
            offset += 16
            data0 = xor(data0, data1)
            data0 = des.encrypt(data0)
        des2 = mydes.DES()
        des2.setkey(key[16:])
        data0 = des2.decrypt(data0)
        data0 = des.encrypt(data0)
        return data0

    if type == 1:
        mac = unio_mac(data, key)
        mac = mac.encode().hex()[:16]
    elif type == 2:
        mac = unio_mac(data, key)
    elif type == 3:
        mac = custom_mac(data, key)
        mac = mac.encode().hex()[:16]
    elif type == 4:
        mac = custom_mac(data, key)

    return mac

if __name__ == '__main__':
    macdata = '0200302006C020C09A9300000000000000000800000805100001001237621700\
7200027791097D24032207441020000031303031383739353838303130303039393838313830373\
13536A5EA97BC58D75BD7200000000000000001029F2608298F947538677E2A9F3704000319629F\
3602005982027C009F101307010103A0A000010A010000000000866229C9950580000008009F330\
390C8C09F02060000000000089A031511269C01005F2A0201569F2701809F1A0201569F03060000\
000000000002303200082200000100224144545F353534315F3030313935395F303031393835'
    key = '5E193BFEF497CB2F'
    mac = mac_calc(macdata, key, 1)
    print(mac, '4633413333383837')
