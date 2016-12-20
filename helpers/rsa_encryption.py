import rsa
import os
import base64


def is_signature_valid(signature):
    file_exist = os.path.isfile('publicKey.pem')
    if not file_exist:
        raise IOError('publicKey.pem not found in root folder.')

    with open('publicKey.pem') as pub_file:
        data = pub_file.read()
    pub_key = rsa.PublicKey.load_pkcs1(data)
    token = '2373665e-367b-4086-ac08-3849dab94006'

    signature_value = base64.b64decode(signature)
    valid = rsa.verify(token.encode('utf-8'), signature_value, pub_key)
    return valid
