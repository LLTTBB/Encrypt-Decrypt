# Encriptador de Contraseñas

Este es un programa simple desarrollado en Python que te permite agregar contraseñas, calcular sus hashes y desencriptar hashes previamente guardados y encriptados. Es útil para gestionar contraseñas y verificar la integridad de las mismas mediante el uso de funciones hash.

## Características

- **Agregar Contraseña:** Puedes agregar una nueva contraseña utilizando la interfaz gráfica proporcionada.
- **Calcular Hashes:** Calcula varios tipos de hashes (MD5, SHA1, SHA224, SHA256, SHA384, SHA512) para la contraseña ingresada.
- **Desencriptar Hash:** Puedes ingresar un hash y seleccionar el tipo de encriptación para buscar coincidencias en un archivo de contraseñas previamente guardado y encriptado.
- **Modo Oscuro:** La aplicación cuenta con un modo oscuro para una experiencia visual más cómoda.

## Requisitos

- Python 3.x
- Pillow (para instalar, ejecutar `pip install pillow`)

## Uso

1. Ejecuta el archivo `encriptador_contraseña.py`.
2. Agrega contraseñas haciendo clic en el botón "Agregar Contraseña" e ingresando la contraseña en el campo proporcionado.
3. Calcula hashes haciendo clic en el botón "Calcular Hashes".
4. Para desencriptar un hash, ingresa el hash en el campo "Hash a Desencriptar", selecciona el tipo de encriptación y haz clic en el botón "Desencriptar Hash".
5. Disfruta de una gestión sencilla y segura de tus contraseñas.

## Contribución

¡Las contribuciones son bienvenidas! Si encuentras algún problema o tienes sugerencias de mejoras, no dudes en abrir un issue o enviar un pull request.
