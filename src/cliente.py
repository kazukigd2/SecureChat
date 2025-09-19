from SecureChat.securechat import SecureChat
import threading

def recibir_mensajes(cliente, nombre_usuario):
    while True:
        try:
            print("\r", end="", flush=True)  # Mueve el cursor al principio de la línea

            nombreDelOtro, mensaje = cliente.recibirMensaje(True)

            print(f"{nombreDelOtro} > " + f"{mensaje}", flush=True)
            
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error al recibir mensaje: {e}")
            break

def main():
    nombre_usuario = input("Eres el cliente, Ingresa tu nombre: ")  # Pide al usuario que ingrese su nombre
    cliente = SecureChat(nombre_usuario, is_server=False, ip="127.0.0.1", port=5551)
    cliente.conectarCliente()

    # Hilo para recibir mensajes
    hilo_recibir = threading.Thread(target=recibir_mensajes, args=(cliente, nombre_usuario))
    hilo_recibir.daemon = True
    hilo_recibir.start()

    try:
        while True:
            mensaje = input()
            if mensaje.lower() in ['exit', 'salir']:
                break
            cliente.enviarMensaje((mensaje), True)
    except KeyboardInterrupt:
        pass
    finally:
        cliente.cerrarConexion()

if __name__ == "__main__":
    main()