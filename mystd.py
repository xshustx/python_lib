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
