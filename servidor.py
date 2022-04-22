import firmas
import sys
import socket
import RSA
import AES
import hmac
import llaves


def socket_servidor(puerto):
    mySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # hace el bind en cualquier interfaz disponible
    mySocket.bind(('', int(puerto)))
    return mySocket


def esperar_cliente(servidor):
    servidor.listen(1)
    cliente, addr = servidor.accept()
    return cliente


def extraccion_aes_iv_mac(llaves_descifradas):
    llave_aes = llaves_descifradas[:16]
    llaves_descifradas = llaves_descifradas[16:]
    llave_mac = llaves_descifradas[16:]
    iv = llaves_descifradas[:16]
    return llave_aes, iv, llave_mac


def verificar_firma(signature, mensaje, llave_publica_servidor):
    return firmas.validar_firma(llave_publica_servidor, signature, mensaje)


def recalcular_mac(transmision, llave_mac):
    return hmac.regresar_mac(transmision, llave_mac)


def verificar_mac(hmac_mensaje, hmac_recv):
    if hmac_mensaje != hmac_recv:
        print('Las mac no coinciden')
        exit(1)
    print("Las MAC coinciden")
    return 0


def descifrar_llaves(mensaje_cifrado, llave_privada_cliente):
    llaves_descifradas = RSA.descifrar(mensaje_cifrado, llave_privada_cliente)
    return llaves_descifradas


def separar_mensaje(mensaje, llave_privada_cliente, llave_publica_servidor):
    llaves_privadas = mensaje[:256]
    mensaje = mensaje[256:]
    signature = mensaje[:256]
    mensaje = mensaje[256:]
    mac_recv = mensaje[-32:]
    mensaje_cliente = mensaje[:11]
    # Descifrado de llaves
    llaves_privadas_descifradas = descifrar_llaves(llaves_privadas, llave_privada_cliente)
    # Extracción AES, IV , MAC
    aes, iv, mac = extraccion_aes_iv_mac(llaves_privadas_descifradas)
    # Verificando las firmas
    verificar_firma(signature, aes+iv+mac, llave_publica_servidor)
    # Verificando la MAC
    mac_recalculada = recalcular_mac(llaves_privadas+signature+mensaje_cliente, mac)
    verificar_mac(mac_recalculada, mac_recv)
    mensaje_descifrado = AES.descifrar(mensaje_cliente, aes, iv)
    print(mensaje_descifrado)     


if __name__ == '__main__':
    servidor = socket_servidor(sys.argv[1])
    cliente = esperar_cliente(servidor)
    # Llave CLIENTE
    path_llave_privada_cliente = sys.argv[2]
    llave_privada_cliente = llaves.recuperar_privada_from_path(path_llave_privada_cliente)
    # Llave SERVIDOR
    path_llave_publica_servidor = sys.argv[3]
    llave_publica_servidor = llaves.recuperar_publica_from_path(path_llave_publica_servidor)
    # Conexión con el cliente
    # Recibiendo el mensaje
    mensaje = cliente.recv(4096)
    separar_mensaje(mensaje, llave_privada_cliente, llave_publica_servidor)

    cliente.close()
    servidor.close()
