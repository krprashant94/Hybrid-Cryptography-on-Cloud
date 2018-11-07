# -*- coding: utf-8 -*-
#Created on Sun Oct 21 23:09:06 2018
#Author Prashant
"""
Serial Module
--------------

This module encapsulates the access for the serial port. It support Python
running on Windows, OSX, Linux, BSD.
This module can only used for reading RSA, AES, DES and Shift Cipher Key
from Serial port.

Dependencies:
    - pyserial
        >>> python -m pip install pyserial
Uses:
    >>> import securefile.secureserial
    >>> from securefile.keyset import RSA_KEY
"""
# In[]
from base64 import b64decode
import serial
from serial.tools import list_ports as com_ports
# In[]

class ScanResult:
    """
    A class for decrypting and stroing the key which is recived
    from serial port.
    """

    des_key = 'des_key'
    """
    DES key value
    """
    aes_key = 'aes_key'
    """
    AES key value
    """
    rsa_tuple = (0, 0)
    """
    RSA key values as tuple.
    """
    shift = 0
    """
    Shift value for ceser cipher
    """

    def __init__(self, scan):
        """
        Recived String from Hardware Key

        :param str scan: Scan string
        :returns: None
        :raises: None
        """
        try:
            scan = b64decode(scan)
            scan = eval(scan)
            self.des_key = scan[0]
            self.aes_key = scan[1]
            self.rsa_tuple = scan[2].split(':')
            self.shift = int(scan[3])
        except Exception:
            raise ValueError("Wrong Device selected...")

    def get_des(self):
        """Returns DSA key value"""
        return self.des_key

    def get_aes(self):
        """Returns AES key value"""
        return self.aes_key

    def get_rsa(self):
        """Returns RSA key tuple"""
        return self.rsa_tuple

    def get_shift(self):
        """Returns shift value in shift cipher"""
        return self.shift

class SerialPort:
    """
    SerialPort
    ----------
    Serial port class for reading the data form serial COM port
    **Required**

    >>> import serial
    >>> import serial.tools.list_ports as com_ports
    """
    def __init__(self):
        """
        Create a SerialPort object to get form serial (COM) port

        :returns: None
        :raises: None
        """
        self.ports = []
        self.desc = []
        self.ser = False

    def scan(self, console_log=False):
        """
        Scan all available port and return the result

        :param bool console_log=True: Log the result in console
        :returns: `[list, list]` list of open port and its discription
        :raises: None
        """
        if console_log:
            print("Available ports : \nPort\t\t   Hardwere")
            print("---------------------------------------")
        for port in com_ports.comports():
            self.ports.append(port.device)
            self.desc.append(port.description)
            if console_log:
                print(port.device+'\t\t'+port.description)
        if console_log:
            print("---------------------------------------")
        return self.ports, self.desc

    def open(self, port):
        """
        Creates a object for serial port and initilize that port
        and open serial port for communication.
        :class:`~securefile.serial.SerialPort.ready()`

        :param str port: port number
        :returns: None
        :raises SerialException: if the port cannot be opened.
        :raises NameError: if port does not exist.
        """
        if port in self.ports:
            self.ser = serial.Serial()
            self.ser.port = port
            self.ser.open()
        else:
            self.close()
            raise NameError(port+" port not found in available port.")

    def close(self):
        """
        close active serial port

        :returns: None
        :raises: None
        """
        if self.ser:
            self.ser.close()
            self.ser = False

    def read_key(self, console_log=False):
        """
        Get one key from serial port

        :returns: :class:`~securefile.secureserial.ScanResult` data form serial port
        :raises: None
        """
        if self.ser:
            data = self.ser.readline().decode().strip()
            data = self.ser.readline().decode().strip()
            if console_log:
                print(data)
            scr = ''
            try:
                scr = ScanResult(data)
            except ValueError:
                self.close()
                raise ValueError("Unable to decode the hardware. Wrong hardware found.")
            return scr
        raise ValueError("No port is open")

# In[]:
if __name__ == '__main__':
    SP = SerialPort()
    SCAN_LIST = SP.scan(console_log=True)
    if SCAN_LIST:
        SP.open("COM3")
        SP.read_key()
        SP.close()
