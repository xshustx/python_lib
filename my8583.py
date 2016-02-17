from ISO8583.ISO8583 import ISO8583
from ISO8583.ISOErrors import *


class MY8583(ISO8583):
    def __init__(self):
        self.iso = ISO8583()
        self.HeaderLen = 2

    def paser(msg):
        self.msginfo, msg = cut(msg, 12)
        self.dest = '0004'
        self.src = '0000'
        self.id = '60'
        self.msghlen = self.HeaderLen + len(self.id + self.dest + self.src + self.msgheader)
        self.msgheader = self.id + self.dest


def show8583(iso):
    print('\n\nMTI = %s' % iso.getMTI())
    print('Bitmap = %s\n' % iso.getBitmap().upper())
    # print ('This ISO has bits:')
    field = iso.getBitsAndValues()
    for x in field:
        # print ('Bit %s %s of type %s with value =
        #         %s' % (x['bit'],x['name'],x['type'],x['value']))
        output = x['bit'].ljust(5, ' ')
        # output = output + x['type'].ljust(20, ' ')
        output = output + x['name'].ljust(50, ' ')
        output += x['value']
        print(output)
    # print('raw: ', iso.getRawIso())

headerlen = 26

def get8583(netpack):
    pack8583 = netpack[headerlen:]
    print('\n\n\n8583 package', pack8583)
    iso = ISO8583()
    # iso.DEBUG = True
    iso.setIsoContent(pack8583)
    show8583(iso)
    return iso