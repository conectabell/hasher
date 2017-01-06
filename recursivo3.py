import os
import hashlib


walk_dir = "/home/user/Escritorio/my/Python/Directorios/"


def hasher(w, t, c="str"):
    #Condicionales para los archivos
    if (t == "md5") and(c == "file"):
        h = hashArchivo(open(w), hashlib.md5())
        return h
    elif (t == "sha1") and(c == "file"):
        h = hashArchivo(open(w), hashlib.sha1())
        return h
    elif (t == "sha224") and(c == "file"):
        h = hashArchivo(open(w), hashlib.sha224())
        return h
    elif (t == "sha256") and(c == "file"):
        h = hashArchivo(open(w), hashlib.sha256())
        return h
    elif (t == "sha384") and(c == "file"):
        h = hashArchivo(open(w), hashlib.sha384())
        return h
    elif (t == "sha512") and(c == "file"):
        h = hashArchivo(open(w), hashlib.sha512())
        return h
    #Condicionales para los recursivos
    elif (t == "md5") and(c == "recursive"):
        h = hashRecursive(w, hasher=hashlib.md5())
        return h
    elif (t == "sha1") and(c == "recursive"):
        h = hashRecursive(w, hsr=hashlib.sha1())
        return h
    elif (t == "sha224") and(c == "recursive"):
        h = hashRecursive(w, hsr=hashlib.sha224())
        return h
    elif (t == "sha256") and(c == "recursive"):
        h = hashRecursive(w)
        return h
    elif (t == "sha384") and(c == "recursive"):
        h = hashRecursive(w, hsr=hashlib.sha384())
        return h
    elif (t == "sha512") and(c == "recursive"):
        h = hashRecursive(w, hsr=hashlib.sha512())
        return h
        #Condicionales para los lvl1
    elif (t == "md5") and(c == "lvl1"):
        h = hashRecursive(w, hsr=hashlib.md5(), lvl=1)
        return h
    elif (t == "sha1") and(c == "lvl1"):
        h = hashRecursive(w, hsr=hashlib.sha1(), lvl=1)
        return h
    elif (t == "sha224") and(c == "lvl1"):
        h = hashRecursive(w, hsr=hashlib.sha224(), lvl=1)
        return h
    elif (t == "sha256") and(c == "lvl1"):
        h = hashRecursive(w, lvl=1)
        return h
    elif (t == "sha384") and(c == "lvl1"):
        h = hashRecursive(w, hsr=hashlib.sha384(), lvl=1)
        return h
    elif (t == "sha512") and(c == "lvl1"):
        h = hashRecursive(w, hsr=hashlib.sha512(), lvl=1)
        return h


def hashArchivo(archivo, hasher=hashlib.sha256(), blocksize=65536):
    buf = archivo.read(blocksize)
    while len(buf) > 0:
        hasher.update(buf)
        buf = archivo.read(blocksize)
    return hasher.hexdigest()


def hashRecursive(walk_dir, lvl=0, hsr=hashlib.sha256()):
    idl = 0
    hashlist = {}
    #print('walk_dir = ' + walk_dir)
    #print('walk_dir (absolute) = ' + os.path.abspath(walk_dir))
    for root, subdirs, files in os.walk(walk_dir):
        for filename in files:
            file_path = os.path.join(root, filename)
            print "FP: " + file_path
            #archivo = open(file_path, "rb")
            hasha = hashArchivo(open(file_path, "rb"), hasher=hsr)
            print "HASH-A: \n" + hasha + "\nEND-HASH-A-----"
            shsum = hsr.hexdigest()
            print "hsr " + str(hsr)
            #shsum = hsr.hexdigest()
            idl = idl + 1
            hashlist.update([(idl, (file_path, shsum))])
            print file_path + "  -sum: " + shsum
        if lvl == 1:
            return hashlist
    return hashlist

hashRecursive(walk_dir)
print hashArchivo(open("/home/user/Escritorio/my/Python/Directorios/subdir1/my-directory-list.txt", "rb"))
