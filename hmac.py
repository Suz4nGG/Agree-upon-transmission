from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

def regresar_mac(mensaje, llave_mac):    
    h = hmac.HMAC(llave_mac, hashes.SHA256(), backend=default_backend())
    h.update(mensaje)
    return h.finalize()
