# -*- coding: utf-8 -*-
#Utilidad para generar hashes para strings y archivos
import os
import sys
import argparse
import hashlib
import bcrypt
from passlib.apache import HtpasswdFile


descrip = str(""" Hasher:
    Utilidad shell para generar hashes de archivos y strings en Python.
    Puede generar hashes en directorios recursivamente y exportarlo todo a un
    archivo .txt. Puede generar hashes de strings en los siguientes algoritmos:
    md5, sha1, sha224, sha256, sha384, sha512, bcrypt, apr1 y NTLM. Para
    archivos se pueden usar lo siguientes algoritmos: md5, sha1, sha224,
    sha256, sha384 y sha512.
    Creado por Charlie, Antonov o como me quieras llamar para
    www.conectabell.com""")


def hashSHA1(w):
    hash_object = hashlib.sha1(w)
    hex_dig = hash_object.hexdigest()
    return hex_dig


def hashSHA224(w):
    hash_object = hashlib.sha224(w)
    hex_dig = hash_object.hexdigest()
    return hex_dig


def hashSHA256(w):
    hash_object = hashlib.sha256(w)
    hex_dig = hash_object.hexdigest()
    return hex_dig


def hashSHA384(w):
    hash_object = hashlib.sha384(w)
    hex_dig = hash_object.hexdigest()
    return hex_dig


def hashSHA512(w):
    hash_object = hashlib.sha512(w)
    hex_dig = hash_object.hexdigest()
    return hex_dig


def hashMD5(w):
    hash_object = hashlib.md5(w)
    hex_dig = hash_object.hexdigest()
    return hex_dig


def hashNTLM(w):
    hash_object = hashlib.new('md4', w.encode('utf-16le')).hexdigest()
    return hash_object


def hashBCrypt(w):
    hash_object = bcrypt.hashpw(w, bcrypt.gensalt())
    return hash_object


def hashAPR1(w):
    h = HtpasswdFile()
    h.set_password("www-data", w)
    return h.to_string()


def hasher(w, t, c="str"):
    try:
        if (t == "sha256")and(c == "str"):
            h = hashSHA256(w)
            return h
        elif (t == "sha1")and(c == "str"):
            h = hashSHA1(w)
            return h
        elif (t == "sha224")and(c == "str"):
            h = hashSHA224(w)
            return h
        elif (t == "sha384")and(c == "str"):
            h = hashSHA384(w)
            return h
        elif (t == "sha512")and(c == "str"):
            h = hashSHA512(w)
            return h
        elif (t == "md5") and(c == "str"):
            h = hashMD5(w)
            return h
        elif (t == "NTLM") and(c == "str"):
            h = hashNTLM(w)
            return h
        elif (t == "bcrypt") and(c == "str"):
            h = hashBCrypt(w)
            return h
        elif ((t == "apr1") or (t == "apache"))and(c == "str"):
            h = hashAPR1(w)
            return h
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
        else:
            raise Exception("Tipo de hash no soportado para esta funcion")
    except Exception as e:
        print "Error: " + str(e)
        sys.exit()


def hashArchivo(ruta, hasher="sha256"):
    try:
        archivo = open(ruta, "rb")
    except IOError as e:
        return "Error: " + str(e.strerror)
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
            #archivo = open(file_path, "rb")
            hasha = hashArchivo(file_path, hasher=hsr)
            print "HASH-A: " + hasha
            print "Hasher: " + hsr
            idl += 1
            hashlist.update([(idl, (file_path, hasha))])
            #print file_path + "  -sum: " + hasha
        if lvl == 1:
            return hashlist
    return hashlist


def export(lines, filename, make=False):
    if make is True:
        open(filename, "wb")
    with open(filename, "a+b") as arch:
        arch.write(lines)


parser = argparse.ArgumentParser(description=str(descrip))
parser.add_argument("-F", "--file", help="Obtiene el hash de un archivo")
parser.add_argument("-D", "--directory",
    help="Calcula el hash de los archivos de un directorio")
parser.add_argument("-R", "--recursive",
    help="Hace recursivo el hasheo de directorios",
    action="store_true")
parser.add_argument("-S", "--string", help="Devuelve el hash de un string")
parser.add_argument("-H", "--hashtype",
    help="Tipo de hash: md5, sha256, sha512, bcrypt, apache, NTLM...")
parser.add_argument("-X", "--export", help="Exportar a txt")
parser.add_argument("-v", "--verbosity", help="activa la verbosidad",
                    action="store_true")
args = parser.parse_args()
#print args.echo

if not args.hashtype:
    args.hashtype = "sha256"

if args.export:
        export("Conectabell Hasher \nOutput File:\n", args.export, make=True)

if args.file:
    #archivo = open(args.file, "rb")
    ret = hasher(args.file, args.hashtype, c="file")
    print args.file
    print args.hashtype + ": " + str(ret)

if args.string:
    args.hashtype
    ret = hasher(args.string, args.hashtype)
    print args.hashtype + ": " + str(ret)

if args.directory:
    if args.export:
        txt_list = """
>>> Listado y hashes """ + args.hashtype + """:\n----------------------------\n
"""
        export(txt_list, args.export)
    if args.recursive is True:
        ret = hasher(args.directory, args.hashtype, c="recursive")
        for r in ret:
            pr = ret[r][0] + "  -  " + ret[r][1] + "\n"
            print pr
            if args.export:
                export(pr, args.export)
        print str(ret)
    else:
        ret = hasher(args.directory, args.hashtype, c="lvl1")
        #ret = hashRecursive(args.directory, lvl=1)
        for r in ret:
            pr = ret[r][0] + "  -  " + ret[r][1] + "\n"
            print pr
            if args.export:
                export(pr, args.export)
        print str(ret)