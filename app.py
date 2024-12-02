import os
import sqlite3
import keyring
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2


class AESCipher:

    def __init__(self, key):
        self.key = key

    def decrypt(self, text):
        cipher = AES.new(self.key, AES.MODE_CBC, IV=(b' ' * 16))
        return self._unpad(cipher.decrypt(text))

    def _unpad(self, s):
        padding_length = s[-1]
        return s[:-padding_length]


passwd = keyring.get_password('Chrome Safe Storage', 'Chrome')
passwd = passwd.encode()

salt = b'saltysalt'
length = 16
iterations = 1003
key = PBKDF2(passwd, salt, length, iterations)

cipher = AESCipher(key)

cookie_file = os.path.expanduser(
    '~/Library/Application Support/Google/Chrome/Default/Cookies')

conn = sqlite3.connect(cookie_file)
conn.text_factory = bytes
sql = 'SELECT host_key,path,is_secure,name,value,encrypted_value,((expires_utc/1000000)-11644473600) FROM cookies'

if __name__ == '__main__':

    for host_key, path, is_secure, name, _value, encrypted_value, _exptime in conn.execute(sql):

        value = _value
        if encrypted_value[:3] == b'v10':
            encrypted_value = encrypted_value[3:]
            value = cipher.decrypt(encrypted_value)
            value = value[32:].decode('utf-8')

        exptime = max(_exptime, 0)
        secure = str(bool(is_secure)).upper()

        if "adventofcode" in host_key.decode("utf-8"):
            print(host_key, 'TRUE', path, secure, exptime, name, value, sep='\t')


    conn.rollback()

