# Hasher:
Utilidad shell para generar hashes de archivos y strings en Python.
Puede generar hashes en directorios recursivamente y exportarlo todo a un archivo .txt. 
Puede generar hashes de strings en los siguientes algoritmos:
  - md5, sha1, sha224, sha256, sha384, sha512, bcrypt, apr1 y NTLM. 

Para archivos se pueden usar lo siguientes algoritmos: 
  - md5, sha1, sha224, sha256, sha384 y sha512.

##Uso
python hasher.py [-S | -F | -D (-R)] <nombre_archivo> -H <algoritmo> -X <nombre_salida_txt>

-S Obtiene el hash de un string.
-F Obtiene el hash de un archivo.
-D Obtiene el hash de un directorio, si añadimos -R realizamos el escaneo recursivo.
-H Especifica el algoritmo, por defecto sha256. Puedes ver los tipos de algoritmos soportados más arriba.

##Ejemplos

Obtener el hash de una cadena de texto en sha1:
  >python hasher.py -S holamundo -H sha1

Obtener el hash de un fichero en sha224:
  >python hasher.py -F documento.txt -H sha224

Obtener un listado de hashes de un directorio y todos los directorios que contiene:
  >python hasher.py -D /home/user/example/dir/ -R

Creado por Antonov para www.conectabell.com
