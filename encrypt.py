# -*- coding: utf-8 -*-

import sys

reload(sys)
sys.setdefaultencoding("utf-8")

from Crypto.Cipher import AES
from base64 import urlsafe_b64encode, urlsafe_b64decode
import config

class AES256_CBC_PKCS5Padding:
    
    def __init__(self):
        # use 16 as block size
        self.BS = 16
        # set key and iv
        self.key = config.key
        self.iv = config.iv
    
    def add_padding(self, str):
        # apply PKCS5Padding
        return str + chr(self.BS - len(str) % self.BS) * (self.BS - len(str) % self.BS)
    
    def remove_padding(self, str):
        # get padding byte according to the PKCS5Padding
        pb = ord(str[len(str)-1:])
        # remove padding and return it
        return str[:-pb]
    
    def encrypt(self, plain_text, b64 = False, utf_8 = False):
        # use CBC mode
        crypto = AES.new(self.key, AES.MODE_CBC, self.iv)
        # PKCS5 Padding
        padding_text = self.add_padding(plain_text)
        # utf-8 encoding
        if utf_8:
            padding_text = padding_text.encode(encoding='UTF-8')
        # encrypt
        cipher = crypto.encrypt(padding_text)
        # base 64 encoding
        if b64:
            cipher = urlsafe_b64encode(cipher)
        return cipher
    
    def decrypt(self, cipher, b64 = False, utf_8 = False):
        # use CBC mode
        crypto = AES.new(self.key, AES.MODE_CBC, self.iv)
        # base 64 decode
        if b64:
            cipher = urlsafe_b64decode(cipher)
        # decrypt
        padding_text = crypto.decrypt(cipher)
        # utf-8 decoding
        if utf_8:
            padding_text = padding_text.decode(encoding="UTF-8")
        # remove PKCS5 Padding
        plain_text = self.remove_padding(padding_text)
        return plain_text

    def encrypt_file(self, infile_path, outfile_path, chunksize=64*1024):
        # use CBC mode
        crypto = AES.new(self.key, AES.MODE_CBC, self.iv)
        with open(infile_path, 'rb') as infile:
            with open(outfile_path, 'wb') as outfile:
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) < chunksize:
                        outfile.write(crypto.encrypt(self.add_padding(chunk)))
                        break
                    outfile.write(crypto.encrypt(chunk))

    def decrypt_file(self, infile_path, outfile_path, chunksize=64*1024):
        # use CBC mode
        crypto = AES.new(self.key, AES.MODE_CBC, self.iv)
        with open(infile_path, 'rb') as infile:
            with open(outfile_path, 'wb') as outfile:
                prev_chunk = None
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0 and prev_chunk:
                        outfile.write(self.remove_padding(crypto.decrypt(prev_chunk)))
                        break
                    if prev_chunk:
                        outfile.write(crypto.decrypt(prev_chunk))
                    if len(chunk) < chunksize:
                        outfile.write(self.remove_padding(crypto.decrypt(chunk)))
                        break
                    prev_chunk = chunk

e = AES256_CBC_PKCS5Padding()
origin = "Hello World가나다"
c = e.encrypt(origin, b64=False, utf_8=False)
p = e.decrypt(c, b64=False, utf_8=False)
print(origin + " => " + c + " => " + p)

e.encrypt_file("hello.txt", "enc.txt")
e.decrypt_file("enc.txt", "dec.txt")