import os
import hashlib


walk_dir = "/home/antonov/Escritorio/my/Python/Directorios/"


def hasher(w, t, c="str"):
    #Condicionales para los archivos
    if (t == "md5") and(c == "file"):
        h = hashArchivo(w, t)
        return h
    elif (t == "sha1") and(c == "file"):
        h = hashArchivo(w, t)
        return h
    elif (t == "sha224") and(c == "file"):
        h = hashArchivo(w, t)
        return h
    elif (t == "sha256") and(c == "file"):
        h = hashArchivo(w, t)
        return h
    elif (t == "sha384") and(c == "file"):
        h = hashArchivo(w, t)
        return h
    elif (t == "sha512") and(c == "file"):
        h = hashArchivo(w, t)
        return h
    #Condicionales para los recursivos
    elif (t == "md5") and(c == "recursive"):
        h = hashRecursive(w, hsr=t)
        return h
    elif (t == "sha1") and(c == "recursive"):
        h = hashRecursive(w, hsr=t)
        return h
    elif (t == "sha224") and(c == "recursive"):
        h = hashRecursive(w, hsr=t)
        return h
    elif (t == "sha256") and(c == "recursive"):
        h = hashRecursive(w)
        return h
    elif (t == "sha384") and(c == "recursive"):
        h = hashRecursive(w, hsr=t)
        return h
    elif (t == "sha512") and(c == "recursive"):
        h = hashRecursive(w, hsr=t)
        return h
        #Condicionales para los lvl1
    elif (t == "md5") and(c == "lvl1"):
        h = hashRecursive(w, hsr=t, lvl=1)
        return h
    elif (t == "sha1") and(c == "lvl1"):
        h = hashRecursive(w, hsr=t, lvl=1)
        return h
    elif (t == "sha224") and(c == "lvl1"):
        h = hashRecursive(w, hsr=t, lvl=1)
        return h
    elif (t == "sha256") and(c == "lvl1"):
        h = hashRecursive(w, lvl=1)
        return h
    elif (t == "sha384") and(c == "lvl1"):
        h = hashRecursive(w, hsr=t, lvl=1)
        return h
    elif (t == "sha512") and(c == "lvl1"):
        h = hashRecursive(w, hsr=t, lvl=1)
        return h


def hashArchivo(ruta, hasher="sha256"):
    archivo = open(ruta, "rb")
    buf = archivo.read()
    if hasher == "sha256":
        ret = hashlib.sha256(buf).hexdigest()
    elif hasher == "md5":
        ret = hashlib.md5(buf).hexdigest()
    elif hasher == "sha1":
        ret = hashlib.sha1(buf).hexdigest()
    elif hasher == "sha224":
        ret = hashlib.sha224(buf).hexdigest()
    elif hasher == "sha384":
        ret = hashlib.sha384(buf).hexdigest()
    elif hasher == "sha512":
        ret = hashlib.sha512(buf).hexdigest()
    elif not hasher:
        ret = "Especifique un tipo de hash"
    else:
        ret = "Tipo de hash no soportado"
    return ret


def hashRecursive(walk_dir, lvl=0, hsr="sha256"):
    idl = 0
    hashlist = {}
    #print('walk_dir = ' + walk_dir)
    #print('walk_dir (absolute) = ' + os.path.abspath(walk_dir))
    for root, subdirs, files in os.walk(walk_dir):
        for filename in files:
            file_path = os.path.join(root, filename)
            print "Ruta: " + file_path
            archivo = open(file_path, "rb")
            hasha = hashArchivo(archivo, hasher=hsr)
            print "HASH-A: " + hasha
            print "Hasher: " + hsr
            idl += 1
            hashlist.update([(idl, (file_path, hasha))])
            #print file_path + "  -sum: " + hasha
        if lvl == 1:
            return hashlist
    return hashlist

hashRecursive(walk_dir)
print hashArchivo(open("/home/antonov/Escritorio/my/Python/Directorios/subdir1/my-directory-list.txt", "rb"))