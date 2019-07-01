
#pip3 install PyCryptodome

import json
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_Signer
from Crypto.Hash import SHA256
from base64 import b64decode
from base64 import b64encode
import requests


PARTNER_TOKEN = "Partner_token"

PRIVATE_KEY = '''-----BEGIN RSA PRIVATE KEY-----
private_key
-----END RSA PRIVATE KEY-----'''

PUBLIC_KEY = '''-----BEGIN PUBLIC KEY-----
public_key
-----END PUBLIC KEY-----'''

BLOCK_SIZE = 16
URL = 'URL'


def generate_xpay_auth_request_data(**kwargs):
    request_data = kwargs.get('request_data')
    encryption_key = get_random_bytes(BLOCK_SIZE)
    iv = get_random_bytes(BLOCK_SIZE)
    encryptor = AES.new(encryption_key, AES.MODE_CBC, iv)
    encrypted_request_data = b64encode(iv + encryptor.encrypt(pad(request_data.encode('utf-8'),
                                                                  BLOCK_SIZE)))
    imported_public_key = RSA.importKey(PUBLIC_KEY)
    cipher = PKCS1_v1_5.new(imported_public_key)
    cipher_text = cipher.encrypt(encryption_key)
    encrypted_aes_key = b64encode(cipher_text)

    imported_private_key = RSA.import_key(PRIVATE_KEY)
    signer = PKCS1_v1_5_Signer.new(imported_private_key)
    digest = SHA256.new()
    digest.update(b64decode(encrypted_aes_key))
    sign = signer.sign(digest)
    signed_key = b64encode(sign)
    return {'Sign': signed_key.decode('utf-8'),
            'KeyAES': encrypted_aes_key.decode('utf-8'),
            'Data': encrypted_request_data.decode('utf-8')}


if __name__ == '__main__':
    json_data = {'ID': 12345}
    xpay_request_data = generate_xpay_auth_request_data(request_data=json.dumps(json_data))
    xpay_request_data['Partner'] = {}
    xpay_request_data['Partner']['PartnerToken'] = PARTNER_TOKEN
    xpay_request_data['Partner']['OperationType'] = 12345
    response = requests.post(URL, data=json.dumps(xpay_request_data))
    print(response.text)


