from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def firmar(message, private_key):
    signature = private_key.sign(message,
                              padding.PSS(
                                  mgf=padding.MGF1(hashes.SHA256()),
                                  salt_length=padding.PSS.MAX_LENGTH),
                              hashes.SHA256())
    return signature

def validar_firma(public_key, signature, message):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
    except:
        print("Firmas invalidas")
        return False
        exit(1)
    print("Firmas validas")
    return True
