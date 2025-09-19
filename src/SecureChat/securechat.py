import socket
from . import funciones_rsa
from . import funciones_aes
from . import socket_class
from Crypto.Random import get_random_bytes
import json 
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA

class SecureChat:
    def __init__(self, nombre, is_server=False, ip='127.0.0.1', port=5551):
        self.is_server = is_server
        self.ip = ip
        self.port = port
        self.nombreDelOtro = None

        self.K1 = None
        self.K2 = None
        self.nombre = nombre

        self.nonceServidor = None
        self.nonceCliente = None

        self.PK_Propio = None
        self.SK_Propio = None
        self.PK_Recibida = None

        self.socket = socket_class.SOCKET_SIMPLE_TCP(ip, port)
        self.aes_cifrado = None
        self.aes_descifrado = None

    def conectarServidor(self):
        self.crearClaves()
        print(self.nombre + " Es el servidor, esperando al cliente...")
        self.socket.escuchar()
        self.intercambioDeClaves()

        # El servidor recoge los mensajes del cliente recibidos y sus claves con las que se comunicaran
        self.K1 = self.socket.recibir()
        self.K2 = self.socket.recibir()
        self.K1 = funciones_rsa.descifrarRSA_OAEP(self.K1, self.SK_Propio)
        self.K2 = funciones_rsa.descifrarRSA_OAEP(self.K2, self.SK_Propio)
        self.K1 = bytes.fromhex(self.K1)
        self.K2 = bytes.fromhex(self.K2)
        firmaK1K2_Recibido = self.socket.recibir()

        #El servidor desencripta las claves privadas los K1, K2 y comprueba que la firma HMAC sea correcta
        if not funciones_rsa.comprobarRSA_PSS( (self.K1 + self.K2), firmaK1K2_Recibido, self.PK_Recibida):
            print("Error: La firma de K1 y K2 no es válida.")
            self.socket.cerrar()
            return

        #El servidor recibe los mensajes nuevos del cliente y el HMAC
        IV = self.socket.recibir()
        MensajeRecibidoCifrado = self.socket.recibir()
        HMACRecibida = self.socket.recibir()
    
        aes_descifradoCBC = funciones_aes.iniciarAES_CBC_descifrado(self.K1, IV)
        MensajeRecibido = funciones_aes.descifrarAES_CBC(aes_descifradoCBC,MensajeRecibidoCifrado)

        #Valida el HMAC
        if not self.validarHMAC(self.K2, MensajeRecibidoCifrado, HMACRecibida):
            print("El mensaje ha sido modificado o la clave HMAC es incorrecta.")
            return

        #Captura el nonce del jSon recibido para comunicarnos por aes con CTR
        MensajeRecibido = json.loads(MensajeRecibido) # Recuperamos un Array Python de un string
        nombreCliente, nonce_cadenaHEX = MensajeRecibido
        self.nonceCliente = bytearray.fromhex(nonce_cadenaHEX) # De Hexadecimal a Bytes
        self.nombreDelOtro = nombreCliente

        #El servidor responde al cliente cifra simetricamente "Servidor + Cliente + nounce"
        mensaje = [] # Array vacio
        mensaje.append(nombreCliente) # Donde alice == “Alice”
        mensaje.append(self.nombre)
        mensaje.append(self.nonceCliente.hex()) # Conversion de Bytes a Hexadecimal
        jStr = json.dumps(mensaje) # Convertimos un Array Python a string

        aes_cifradoCBC, IV2 = funciones_aes.iniciarAES_CBC_cifrado(self.K1)
        mensajeCifrado = funciones_aes.cifrarAES_CBC(aes_cifradoCBC, jStr)
        self.aes_cifrado, self.nonceServidor = funciones_aes.iniciarAES_CTR_cifrado(self.K1)

        #El servidor crea el HMAC del mensaje
        firma = self.firmaHMAC(self.K2,mensajeCifrado)

        #El cliente envia el mensaje y el HMAC
        self.socket.enviar(mensajeCifrado)
        self.socket.enviar(firma)
        self.socket.enviar(IV2)
        self.socket.enviar(self.nonceServidor)

        self.aes_descifrado = funciones_aes.iniciarAES_CTR_descifrado(self.K1, self.nonceCliente)

        print("Conexion establecita por parte de " + self.nombre + "... ")

    def conectarCliente(self):
        self.crearClaves()
        print(self.nombre + " Como cliente quiere conectarse...")
        self.socket.conectar()
        self.intercambioDeClaves()

        #El cliente genera 2 claves simetricas
        self.K1 = funciones_aes.crear_AESKey()
        self.K2 = funciones_aes.crear_AESKey()

        #El cliente cifra las 2 claves sunetricas con la clave publica del servidor 
        # y firma la concatenacion de ambas con su clave privada con HMAC de SHA256
        cifradoK1 = funciones_rsa.cifrarRSA_OAEP(self.K1.hex(), self.PK_Recibida)
        cifradoK2 = funciones_rsa.cifrarRSA_OAEP(self.K2.hex(), self.PK_Recibida)
        firma_K1K2 = funciones_rsa.firmarRSA_PSS((self.K1 + self.K2), self.SK_Propio)


        # El cliente envia el mensaje con los cifrados de K1, K2 y la firma de ambas y Bob las recoge
        self.socket.enviar(cifradoK1)
        self.socket.enviar(cifradoK2)
        self.socket.enviar(firma_K1K2)

        # El cliente cifra simetricamente "Nombre + nounce"
        self.aes_cifrado, self.nonceCliente = funciones_aes.iniciarAES_CTR_cifrado(self.K1)
        mensaje = [] # Array vacio
        mensaje.append(self.nombre) # Donde nombre == “Nombre”
        mensaje.append(self.nonceCliente.hex()) # Conversion de Bytes a Hexadecimal
        jStr = json.dumps(mensaje) # Convertimos un Array Python a string

        aes_cifradoCBC, self.IV = funciones_aes.iniciarAES_CBC_cifrado(self.K1)
        mensajeCifrado = funciones_aes.cifrarAES_CBC(aes_cifradoCBC, jStr)
    
        #El cliente crea el HMAC del mensaje
        firma = self.firmaHMAC(self.K2, mensajeCifrado)

        #El cliente envia el mensaje y el HMAC
        self.socket.enviar(self.IV)
        self.socket.enviar(mensajeCifrado)
        self.socket.enviar(firma)

        #El cliente recibe los mensajes nuevos del servidor y el HMAC
        MensajeRecibidoCifrado = self.socket.recibir()
        HMACRecibida = self.socket.recibir()
        IV2 = self.socket.recibir()
        self.nonceServidor = self.socket.recibir()

        aes_descifradoCBC = funciones_aes.iniciarAES_CBC_descifrado(self.K1, IV2)
        MensajeRecibido = funciones_aes.descifrarAES_CBC(aes_descifradoCBC, MensajeRecibidoCifrado)

        #Valida el HMAC
        if not self.validarHMAC(self.K2, MensajeRecibidoCifrado, HMACRecibida):
            print("El mensaje ha sido modificado o la clave HMAC es incorrecta.")
            return

        #Captura el nonce del jSon recibido para comunicarnos por aes con CTR
        MensajeRecibido = json.loads(MensajeRecibido) # Recuperamos un Array Python de un string
        nombrePropio, nombreCliente, nonce_cadenaHEX = MensajeRecibido
        nonceRecibido = bytearray.fromhex(nonce_cadenaHEX) # De Hexadecimal a Bytes
        self.nombreDelOtro = nombreCliente

        if (nombrePropio != self.nombre) or (self.nonceCliente != nonceRecibido):
            print("Mensajes no validos")
            return

        self.aes_descifrado = funciones_aes.iniciarAES_CTR_descifrado(self.K1, self.nonceServidor)

        print("Conexion establecita por parte de " + self.nombre + "... ")

    def crearClaves(self):
        # Crear una clave pública y una clave privada RSA de 2048 bits para Alice. Guardar cada clave en un fichero. 
        key = funciones_rsa.crear_RSAKey()
        funciones_rsa.guardar_RSAKey_Privada(('rsa_' + self.nombre + ".pem"), key, self.nombre)
        funciones_rsa.guardar_RSAKey_Publica(('rsa_' + self.nombre + ".pub"), key)
        self.PK_Propio = funciones_rsa.cargar_RSAKey_Publica('rsa_' + self.nombre + '.pub')
        self.SK_Propio = funciones_rsa.cargar_RSAKey_Privada('rsa_' + self.nombre + '.pem', self.nombre)
        self.PK_Propio = self.SK_Propio.export_key(format='DER')

    def firmaHMAC(self, key, mensaje):
        h = HMAC.new(key, digestmod=SHA256)
        h.update(mensaje)
        return h.digest()

    def validarHMAC(self, key, mensaje, mac):
        h = HMAC.new(key, digestmod=SHA256)
        h.update(mensaje)
        try:
            h.verify(mac)
            return True
        except ValueError:
            print("Soy " + self.nombre + ", el mensaje recibido no es autentico")
            return False

    def intercambioDeClaves(self):
        self.socket.enviar(self.PK_Propio)
        self.PK_Recibida = self.socket.recibir()
        self.PK_Recibida = RSA.import_key(self.PK_Recibida)

    def enviarMensaje(self, mensajeOriginal, chat=False):
        mensaje = json.dumps([mensajeOriginal])
        mensajeCifrado = funciones_aes.cifrarAES_CTR(self.aes_cifrado, mensaje.encode());
        firma = self.firmaHMAC(self.K2,mensajeCifrado)
        self.socket.enviar(mensajeCifrado)
        self.socket.enviar(firma)
        if(chat == False):
            print(self.nombre + "> " + mensajeOriginal + " (E)")

    def recibirMensaje(self, chat=False):
        mensajeRecibidoCifrado = self.socket.recibir()
        HMACRecibida = self.socket.recibir()
        mensajeRecibido = funciones_aes.descifrarAES_CTR(self.aes_descifrado, mensajeRecibidoCifrado)

        if not self.validarHMAC(self.K2, mensajeRecibidoCifrado, HMACRecibida):
            print("El mensaje ha sido modificado o la clave HMAC es incorrecta.")
            return

        mensajeFinal = json.loads(mensajeRecibido)   
        mensajeFinal = mensajeFinal[0]
        if(chat == False):
            print(self.nombreDelOtro + "> " + mensajeFinal + " (R)")
        return self.nombreDelOtro, mensajeFinal

    def cerrarConexion(self):
        self.socket.cerrar()
        print("\n" + self.nombre + "> cerrando conexion")