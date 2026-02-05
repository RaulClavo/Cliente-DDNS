# Cliente DDNS

Este programa es un cliente DDNS básico para gestionar registros de [Spaceship](https://www.spaceship.com/).

La interfaz es **intuitiva y autoexplicativa**, por lo que basta con añadir un perfil rellenando los campos y usar los botones de Activar/Desactivar para mantener actualizado el DNS con tu IP pública.

## Ejecución

Aunque el programa se puede ejecutar directamente con los archivos `DDNSClient.py` y `profiles.json`, lo recomendable para uso normal es generar un ejecutable único.

### Opción 1: Ejecutar con Python

1. Asegúrate de tener Python instalado (también las librerías necesarias).
2. Coloca `DDNSClient.py` y `profiles.json` en la misma carpeta.
3. Ejecuta `DDNSClient.py`.
   

### Opción 2: Crear un .exe con PyInstaller (recomendado)

Lo más cómodo es empaquetar la aplicación en un único archivo `.exe` usando el fichero de especificación ya preparado.

Desde la carpeta del proyecto, ejecuta:

```bash
pyinstaller DDNSClient.spec
```

Esto generará un ejecutable en la carpeta `dist` que podrás usar sin necesidad de instalar Python ni dependencias adicionales en cualquier otro equipo destino.
