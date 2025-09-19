from SecureChat.securechat import SecureChat
import threading


def recibir_mensajes(servidor, nombre_usuario):
    while True:
        try:
            print("\r", end="", flush=True)  # Mueve el cursor al principio de la línea

            nombreDelOtro, mensaje = servidor.recibirMensaje(True)

            print(f"{nombreDelOtro} > " + f"{mensaje}", flush=True)
            

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error al recibir mensaje: {e}")
            break

def main():
    nombre_usuario = input("Eres el servidor, Ingresa tu nombre: ")  # Pide al usuario que ingrese su nombre
    servidor = SecureChat(nombre_usuario, is_server=True, port=5551)
    servidor.conectarServidor()

    # Hilo para recibir mensajes
    hilo_recibir = threading.Thread(target=recibir_mensajes, args=(servidor, nombre_usuario))
    hilo_recibir.daemon = True
    hilo_recibir.start()

    try:
        while True:
            mensaje = input()
            if mensaje.lower() in ['exit', 'salir']:
                break
            servidor.enviarMensaje((mensaje), True)
    except KeyboardInterrupt:
        pass
    finally:
        servidor.cerrarConexion()

if __name__ == "__main__":
    main()