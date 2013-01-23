#!/usr/bin/env python
##
## pam_minitotp.py for PAM MiniOTP in /home/rohja/Projects/pam_miniotp
## 
## Made by Paul "Rohja" Lesellier
## Login   <rohja@rohja.com>
## 
## Started on  Tue Jan 22 16:21:49 2013 paul lesellier
##

import syslog
import hmac
import time
import base64
import struct
import hashlib
import os

# OTP

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

# Tools

def read_config_file(pamh):
    config_path = os.path.join("/home/", pamh.user, ".pam_otpsecret")
    syslog.syslog("[+] Reading configuration file: %s." % config_path)
    if not os.path.isfile(config_path):
        syslog.syslog("[x] Configuration file %s is not a file or don't exist." % config_path)
        send_error_msg(pamh, "Error with configuration file.")
        return False
    try:
        config_file = open(config_path)
    except IOError, e:
        syslog.syslog("[x] Configuration file error: %s" % e.strerror)
        send_error_msg(pamh, "Error with configuration file.")
        return False
    config_content = config_file.read()
    return config_content

# Functions

def send_error_msg(pamh, msg):
    return send_msg(pamh, pamh.PAM_ERROR_MSG, "[otp] " + msg)

def send_info_msg(pamh, msg):
    return send_msg(pamh, pamh.PAM_TEXT_INFO, "[otp] " + msg)

def send_msg(pamh, msg_style, msg):
    pammsg = pamh.Message(msg_style, msg)
    rsp = pamh.conversation(pammsg)
    return rsp
def ask_for_password(pamh, prompt):
    passmsg = pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, "%s: " % prompt)
    rsp = pamh.conversation(passmsg)
    return rsp.resp

# PAM

def pam_sm_authenticate(pamh, flags, argv):
    # Get secret
    secret = read_config_file(pamh)
    if not secret:
        send_error_msg(pamh, "No OTP secret for this user.")
        return pamh.PAM_AUTH_ERR
    secret = secret.strip()
    auth_count = 0
    while auth_count < 3:
        # ASK TOTP
        token = ask_for_password(pamh, "TOTP Password")
        if not token:
            send_error_msg(pamh, "No TOTP password entered!")
            return pamh.PAM_AUTH_ERR
        # CHECK TOTP
        otp = OTP(secret)
        try:
            otp_token = str(otp.generate())
        except ValueError:
            send_error_msg(pamh, "Bad secret in configuration.")
            return pamh.PAM_AUTH_ERR
        # IF OK
        if token == otp_token:
            syslog.syslog("Token OK, login allowed!")
            send_info_msg(pamh, "Token OK.")
            return pamh.PAM_SUCCESS
        else:
            syslog.syslog("Bad token, auth_count=%d" % auth_count)
            send_error_msg(pamh, "Bad token.")
            auth_count += 1
    send_error_msg(pamh, "No successful token after 3 try. Logout.")
    return pamh.PAM_AUTH_ERR

def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS
