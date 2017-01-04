# -*- coding: utf-8 -*-
#Utilidad para generar hashes para strings y archivos
import argparse
import hashlib
import bcrypt
from passlib.apache import HtpasswdFile


descrip = str(""" Hasher:
    Utilidad shell para generar hashes de archivos y strings en Python.
    Creado por Charlie para conectabell.com""")


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
    elif (t == "md5") and(c == "file"):
        h = hashArchivo(w, hashlib.md5())
        return h
    elif (t == "sha1") and(c == "file"):
        h = hashArchivo(w, hashlib.sha1())
        return h
    elif (t == "sha224") and(c == "file"):
        h = hashArchivo(w, hashlib.sha224())
        return h
    elif (t == "sha256") and(c == "file"):
        h = hashArchivo(w, hashlib.sha256())
        return h
    elif (t == "sha384") and(c == "file"):
        h = hashArchivo(w, hashlib.sha384())
        return h
    elif (t == "sha512") and(c == "file"):
        h = hashArchivo(w, hashlib.sha512())
        return h


def hashArchivo(archivo, hasher, blocksize=65536):
    buf = archivo.read(blocksize)
    while len(buf) > 0:
        hasher.update(buf)
        buf = archivo.read(blocksize)
    return hasher.hexdigest()


parser = argparse.ArgumentParser(description=str(descrip))
parser.add_argument("-F", "--file", help="Suministra un hash sha256")
parser.add_argument("-S", "--string", help="Devuelve el hash de un string")
parser.add_argument("-H", "--hashtype", help="Tipo de hash: md5, sha256...")
parser.add_argument("-v", "--verbosity", help="activa la verbosidad",
                    action="store_true")
args = parser.parse_args()
#print args.echo

if not args.hashtype:
    args.hashtype = "sha256"

if args.file:
    archivo = open(args.file, "rb")
    ret = hasher(archivo, args.hashtype, c="file")
    print args.file
    print args.hashtype + ": " + str(ret)

if args.string:
    args.hashtype
    ret = hasher(args.string, args.hashtype)
    print args.hashtype + ": " + str(ret)