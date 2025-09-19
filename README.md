# SecureChat

Sistema de comunicación segura entre dos usuarios, donde uno actúa como **servidor** y otro como **cliente**.

La conexión se establece mediante **cifrado asimétrico RSA** para intercambiar de forma segura una **clave simétrica AES-128**. Se utiliza **HMAC** para validar la integridad de los mensajes, asegurando que no sean alterados durante la transmisión. Una vez establecida la conexión, todos los mensajes se cifran simétricamente con **AES-128**, garantizando confidencialidad y seguridad en tiempo real.

---

## Requisitos

- Python 3.x  
- Librería **PyCryptodome** (para AES, RSA, HMAC)

---

## Notas

- No tiene interfaz gráfica; se ejecuta en terminal o consola.  
- Asegúrate de tener **las librerías de Crypto instaladas** antes de ejecutar el sistema.  
- Permite ejecutar un usuario como **servidor** y otro como **cliente**, con mensajes cifrados y verificados automáticamente.
