'''
一些常用功能
'''
import sys


class RedirectionStdout:

    '''
    output redirection
    '''
    __new_stdout = None

    class NewStdout:
        stdout_org = None
        file_handle = None

        def __init__(self):
            self.stdout_org = sys.stdout

        def write(self, data):
            self.stdout_org.write(data)
            if self.file_handle is not None:
                self.file_handle.write(data)

        def flush(self):
            self.stdout_org.flush()
            if self.file_handle is not None:
                self.file_handle.flush()

    def __init__(self):
        self.__new_stdout = self.NewStdout()

    def print_to_file(self, filename, opentype='w'):
        sys.stdout = self.__new_stdout
        self.__new_stdout.file_handle = open(filename, opentype)

    def reset(self):
        sys.stdout = self.__new_stdout.stdout_org


def paserTlv(data):
    '''
    TLV
    TAG, 1 byte
    LEN, N byte. eg. 8101--1  820101--0101
    value
    return [(tag, lens, value), (tag, lens, value), ...]
    '''
    def cut(data, n):
        return data[:n], data[n:]

    def s2i(string):
        return int.from_bytes(bytes.fromhex(string), 'big')

    tlv = []
    while len(data) > 0:
        if len(data) < 4:
            return tlv, False
        tag, data = cut(data, 2)

        lent = ''
        lens, data = cut(data, 2)
        lent += lens
        # print('lens', tag, lens, data)

        lens = s2i(lens)
        # print('leni', lens)

        if lens > 0x80:
            lens = (lens - 0x80) * 2
            if len(data) < lens:
                return tlv, False
            lens, data = cut(data, lens)
            lent += lens
            # print(tag, lens, data)
            lens = s2i(lens) * 2
        # elif lens == 0:
            # return tlv, False
        else:
            lens = lens * 2
        # print('leni', lens)

        if len(data) < lens:
            return tlv, False
        value, data = cut(data, lens)
        # print('tlv: ', tag, lens, value)
        tlv.extend([[tag, lent, value]])
    return tlv, True


def PowerPaserTlv(tlvs):
    i = 0
    # print('a tlvs', tlvs)
    for tlv in tlvs:
        # print('a tlv', tlv)
        if len(tlv[2]) >= 6:
            newtlvs, ok = paserTlv(tlv[2])
            # print('\na, new, ok', newtlvs, ok)
            if ok is True:
                newtlvs = PowerPaserTlv(newtlvs)
                tlvs[i][2] = newtlvs
        i += 1
    # print('a tlvs i', i, tlvs)
    return tlvs


def encodeblue64(data):
    import codecs

    convertlist = {b'0': b'1', b'G': b'G', b'u': b'v', b'K': b'L', b'P': b'Q',
                   b'3': b'4', b'q': b'r', b'/': b'!', b'A': b'A', b'a': b'b',
                   b'C': b'C', b'4': b'5', b'k': b'l', b'c': b'd', b'R': b'S',
                   b'2': b'3', b'y': b'z', b'V': b'W', b'H': b'H', b'o': b'p',
                   b'L': b'M', b'E': b'E', b'J': b'K', b'i': b'j', b'F': b'F',
                   b'+': b'-', b'W': b'X', b'b': b'c', b'e': b'f', b'd': b'e',
                   b'B': b'B', b'1': b'2', b'f': b'g', b'p': b'q', b'v': b'w',
                   b'7': b'8', b'M': b'N', b'X': b'Y', b'9': b',', b'N': b'O',
                   b'j': b'k', b'h': b'i', b't': b'u', b'l': b'm', b'=': b'I',
                   b'T': b'U', b'6': b'7', b'5': b'6', b'z': b'0', b'n': b'o',
                   b'U': b'V', b'Q': b'R', b'8': b'9', b'I': b'J', b'r': b's',
                   b'w': b'x', b'Y': b'Z', b'S': b'T', b'D': b'D', b'Z': b'a',
                   b'm': b'n', b'x': b'y', b's': b't', b'\n': b'', b'g': b'h',
                   b'O': b'P'}
    std64 = codecs.encode(bytes.fromhex(data), 'base64')
    blue64 = b''
    for x in std64:
        b = x.to_bytes(1, 'big')
        if b in convertlist:
            blue64 += convertlist[b]
        else:
            print('need ', b, b.hex())
    # print(blue64, blue64.hex())
    return blue64.decode()


def decodeblue64(data):
    '''
    data, blue64 string
    return,decode hex string
    '''
    import codecs
    conlist = {b'C': b'C', b'2': b'1', b'z': b'y', b'k': b'j', b'0': b'z',
               b't': b's', b'7': b'6', b'O': b'N', b'j': b'i', b'U': b'T',
               b'm': b'l', b'G': b'G', b'n': b'm', b'c': b'b', b'!': b'/',
               b'v': b'u', b'g': b'f', b'b': b'a', b'M': b'L', b'q': b'p',
               b'F': b'F', b'w': b'v', b'P': b'O', b'f': b'e', b'H': b'H',
               b'u': b't', b'E': b'E', b'D': b'D', b'e': b'd', b'1': b'0',
               b'3': b'2', b'N': b'M', b'r': b'q', b'J': b'I', b'd': b'c',
               b'x': b'w', b'B': b'B', b'9': b'8', b'4': b'3', b'V': b'U',
               b'X': b'W', b'a': b'Z', b'h': b'g', b',': b'9', b'l': b'k',
               b'o': b'n', b'8': b'7', b'-': b'+', b'S': b'R', b'i': b'h',
               b'y': b'x', b's': b'r', b'p': b'o', b'L': b'K', b'Q': b'P',
               b'K': b'J', b'I': b'=', b'A': b'A', b'Y': b'X', b'5': b'4',
               b'R': b'Q', b'T': b'S', b'W': b'V', b'Z': b'Y', b'6': b'5'}
    datah = bytes.fromhex(data)
    std64 = b''
    for x in datah:
        b = x.to_bytes(1, 'big')
        if b == b'.':
            break
        if b in conlist:
            std64 += conlist[b]
        else:
            print('need ', b, b.hex())
    org = codecs.decode(std64, 'base64').hex().upper()
    return org


class svn_release:
    __fw_word = '已测固件'
    __key_word = '已测密钥'
    __pp_word = '已测预个人化'
    __name_word = '_密钥文件'

    def set(self, k1, k2, k3, k4):
        self.__fw_word = k1
        self.__key_word = k2
        self.__pp_word = k3
        self.__name_word = k4

    def __svnls(self, url, dirname):
        import subprocess
        cmd_p = 'cmd.exe /k '
        svn_cmd = 'svn ls '
        cmd = cmd_p + svn_cmd + url
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        dirname.clear()
        for line in p.stdout.readlines():
            if line == b'\r\n':
                break
            dirname.extend([line[:-2]])

    def __svnmkdir(self, url):
        import subprocess
        cmd_p = 'cmd.exe /k '
        svn_cmd = 'svn mkdir '
        log = ' -m "script make"'
        cmd = cmd_p + svn_cmd + url + log
        print(cmd)
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in p.stdout.readlines():
            if line == b'\r\n':
                break
            print(line.decode('cp936')[:-2])

    def __svncp(self, src, dst):
        import subprocess
        cmd_p = 'cmd.exe /k '
        svn_cmd = 'svn cp '
        log = ' -m "script make"'
        cmd = cmd_p + svn_cmd + src + ' ' + dst + log
        print(cmd)
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in p.stdout.readlines():
            if line == b'\r\n':
                break
            print(line.decode('cp936')[:-2])

    def __search(self, dirlist, keyword):
        for x in dirlist:
            if keyword in x:
                return x
        return None

    def __getalldir(self, url, dirlist, path=True):
        '''
        只保留文件夹
        文件会被过滤掉
        '''
        dirname = list()
        self.__svnls(url, dirname)
        dirlist.clear()
        i = 0
        for x in dirname:
            x = x.decode('cp936')
            # print(i, x)
            if '/' in x:
                if path is True:
                    a = url + x
                else:
                    a = x[:-1]
                i += 1
                # new = strcut(x, keyword)print(i, a)
                dirlist.extend([a])

    def __strcut(self, string, cut):
        p1 = string.find(cut)
        p2 = p1 + len(cut)
        return string[:p1] + string[p2:]

    def svn_release_one(self, rootpath, destpath, do=False):
        '''
        从rootpath中找到名称中包含__fw_word，__key_word， __pp_word关键字的文件夹

        从destpath找到所有文件夹名

        从__key_word文件夹中去掉__name_word作为名称，对比destpah中所有文件夹...

        ...缺失的，创建，并copy __fw_word, __pp_word 所有文件夹， copy __key_word
        中对应文件夹。

        '''
        # print('search root path dir name:')
        rootpathlist = list()
        self.__getalldir(rootpath, rootpathlist)
        # print(rootpathlist)

        fw = self.__search(rootpathlist, self.__fw_word)
        if fw is None:
            return []

        key = self.__search(rootpathlist, self.__key_word)
        if key is None:
            return []

        pp = self.__search(rootpathlist, self.__pp_word)
        if pp is None:
            return []

        # print('\n---------------------定位到固件，密钥文件和预个人化文件目录：')
        # print(fw)
        # print(key)
        # print(pp)

        # print('\n\r获取固件文件夹列表：')
        fwlist = list()
        self.__getalldir(fw, fwlist)
        # print(fwlist)

        # print('\n\r获取预个人化文件夹列表：')
        pplist = list()
        self.__getalldir(pp, pplist)
        # print(pplist)

        # print('\n\r获取密钥文件夹列表：')
        keylist = list()
        self.__getalldir(key, keylist, False)

        # 可能没有文件只有框架，就无需发布
        if fwlist == [] or pplist == [] or keylist == []:
            return []

        # print('\n\r已经发布的文件：')
        destpathlist = list()
        self.__getalldir(destpath, destpathlist, False)

        newdolist = list()
        for x in keylist:
            keyword = self.__name_word
            if keyword not in x:
                continue  # 非密钥文件

            new = self.__strcut(x, keyword)
            # print('\n\r生成软件生产包名：', new)

            if new in destpathlist:
                continue  # 已经发布

            print('\n\r未发布的文件名：', new)
            destnew = destpath + new
            newdolist.extend([destnew])

            print('\n\r创建svn目录：')
            if do is True:
                self.__svnmkdir(destnew)
            # copy fireware
            srcs = ''
            for one in fwlist:
                # print(one)
                srcs += one + ' '
            for one in pplist:
                # print(one)
                srcs += one + ' '
            # 最后是密钥文件
            print(key+x)
            srcs += key + x

            print('\n\rcopy svn目录：')
            if do is True:
                self.__svncp(srcs, destnew)

        if newdolist != []:
            print('\r\n本次新做：')
            for x in newdolist:
                print(x)
        return newdolist

    def svn_release_all(self, rootpath, destpath, do=False):
        alist = list()
        self.__getalldir(rootpath, alist)
        for x in alist:
            print(x)
        total = list()
        for x in alist:
            a = self.svn_release_one(x, destpath, do)
            total += a
        # print('\r\n====================本次新做：')
        # for x in total:
        #     print(x)
        return total

    def svn_release_mul(self, dicts, do=False):
        mul = list()
        for x in dicts:
            print('\n'+x, dicts[x])
            a = self.svn_release_all(x, dicts[x], do)
            mul += a
        print('\r\n====================本次新做：')
        for x in mul:
            print(x)
        return mul
