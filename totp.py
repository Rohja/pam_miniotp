#!/usr/bin/env python
##
## totp.py for TOTP in /home/rohja/Projects/pam_miniotp
## 
## Made by Paul "Rohja" Lesellier
## Login   <rohja@rohja.com>
## 
## Started on  Tue Jan 22 15:22:26 2013 paul lesellier
##

import sys
import hmac
import time
import base64
import struct
import hashlib

class OTP():
    def __init__(self, secret, counter=None):
        self.secret = secret
        self.counter = counter

    def __hotp(self):
        try:
            secret  = base64.b32decode(self.secret)
        except TypeError:
            raise ValueError("Your secret cannot be used: maybe it's incomplete or invalid.")
        try:
            counter = int(self.counter)
        except ValueError:
            raise ValueError("Your counter need to be a number.")
        counter = struct.pack('>Q', counter)
        hmhash   = hmac.new(secret, counter, hashlib.sha1).digest()
        offset = ord(hmhash[19]) & 0xF
        return (struct.unpack(">I", hmhash[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000

    def __totp(self):
        self.counter = int(time.time()) // 30
        ret = self.__hotp()
        self.counter = None
        return ret

    def generate(self):
        if self.counter is None:
            return self.__totp()
        else:
            return self.__hotp()


def usage(name):
    print "OTP Generator"
    print "USAGE: %s <secret> [<counter>]"

if __name__ == '__main__':
    try:
        if len(sys.argv) == 2:
            otp = OTP(sys.argv[1])
            print otp.generate()
        elif len(sys.argv) == 3:
            otp = OTP(sys.argv[1], sys.argv[2])
            print otp.generate()
        else:
            print usage(sys.argv[0])
    except ValueError, e:
        print "Error: %s" % e.message
