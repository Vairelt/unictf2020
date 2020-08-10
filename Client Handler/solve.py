import socket
from Crypto.Hash import SHA
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
key=RSA.import_key(open("private.der","rb").read())
cipher = PKCS1_v1_5.new(key)

sock=socket.socket()
sock.connect(("trustctf.disasm.me",1234))
sock.send(b"Hello\n")
assert(sock.recv(6)==b"Hello\n")
data = sock.recv(128)
dsize = SHA.digest_size
sentinel = Random.new().read(15+dsize)
message = cipher.decrypt(data, sentinel)
id = message.decode()
data = cipher.encrypt(b"Hello\n")
sock.send(data)
assert(sock.recv(128)==data)
flag=(sock.recv(128)).decode()
print(flag % id)