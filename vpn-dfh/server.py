
import urlfind
from socket import socket, gethostname
from socket import AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from typing import Tuple, Dict
from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import AES, DES, Blowfish
from diffiehellman.diffiehellman import DiffieHellman
import cv2
HOST = gethostname()
PORT = 4600
SUPPORTED_CIPHERS = {"DES": [56]}


def parse_proposal(msg: str) -> Dict[str, list]:

    msg = msg[16:]
    ciphers = {}
    last_c = ''
    cipher_name = ''
    key_size = ''
    curr_key_size_list = []

    for c in msg:
        if c.isalpha():
            cipher_name += c
        elif c.isalnum():
            key_size += c
        elif c in ',':
            if last_c.isalnum():
                curr_key_size_list.append(int(key_size))
                key_size = ''
        elif c == ']':
            curr_key_size_list.append(int(key_size))
            key_size = ''
            ciphers[cipher_name] = curr_key_size_list
            cipher_name = ''
            curr_key_size_list = []
        last_c = c

    return ciphers


def select_cipher(supported: dict, proposed: dict) -> Tuple[str, int]:


    common_ciphers = set(supported.keys()).intersection(proposed.keys())

    cipher = None
    key_size = -1

    if common_ciphers != set():
        for c in common_ciphers:
            current_keysize = max(
                # -1 will be the max value if the intersection is empty
                set([-1]).union(set(supported.get(c)).intersection(proposed.get(c))))
            if current_keysize > key_size:
                key_size = current_keysize
                cipher = c

    if not cipher or key_size == -1:
        raise ValueError(
            'Could not agree on a cipher')

    return (cipher, key_size)


def generate_cipher_response(cipher: str, key_size: int) -> str:

    return "ChosenCipher:{},{}".format(cipher, key_size)


def parse_dhm_request(msg: str) -> int:

    return int(msg.split(':')[1])


def get_key_and_iv(
    shared_key: str, cipher_name: str, key_size: int
) -> Tuple[object, bytes, bytes]:

    cipher_map = {
        "DES": DES, "AES": AES, "Blowfish": Blowfish
    }

    ivlen = {
        "DES": 8, "AES": 16, "Blowfish": 8
    }

    cipher = cipher_map.get(cipher_name)
    key = shared_key[:key_size//8]
    if cipher_name == "DES":
        key += '\0'
    key = key.encode()
    iv = shared_key[-1 * ivlen.get(cipher_name):].encode()

    return cipher, key, iv


def generate_dhm_response(public_key: int) -> str:

    return 'DHMKE:{}'.format(public_key)


def read_message(msg_cipher: bytes, crypto: object) -> Tuple[str, str]:


    ciph_in = msg_cipher[:-64]
    hmac = msg_cipher[-64:].decode('utf-8')
    plaintext = crypto.decrypt(ciph_in).decode('utf-8')
    plaintext = plaintext.strip('\0')
    return plaintext, hmac


def validate_hmac(msg_cipher: bytes, hmac_in: str, hashing: object) -> bool:

    ciphertext = msg_cipher[:-64]
    hashing.update(ciphertext)
    hashvalue = hashing.hexdigest()

    if hashvalue == hmac_in:
        return True
    else:
        raise ValueError('Bad HMAC')


def main():

    # Create the socket
    server_sckt = socket(AF_INET, SOCK_STREAM)
    server_sckt.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    server_sckt.bind((HOST, PORT))
    server_sckt.listen()
    print(f"Listening on {HOST}:{PORT}")
    conn, client = server_sckt.accept()
    print(f"New client: {client[0]}:{client[1]}")

    # Negotiating the cipher
    print("Negotiating the cipher")
    msg_in = conn.recv(4096).decode('utf-8')
    proposed = parse_proposal(msg_in)
    cipher_name, key_size = select_cipher(SUPPORTED_CIPHERS, proposed)
    print(f"We are going to use {cipher_name}{key_size}")
    msg_out = generate_cipher_response(cipher_name, key_size)
    conn.send(msg_out.encode())

    # Negotiating the key
    print("Negotiating the key")
    dh = DiffieHellman()
    dh.generate_public_key()
    msg_in = conn.recv(4096).decode('utf-8')
    client_public_key = parse_dhm_request(msg_in)
    dh.generate_shared_secret(client_public_key)
    msg_out = generate_dhm_response(dh.public_key)
    conn.send(msg_out.encode())
    cipher, key, iv = get_key_and_iv(dh.shared_key, cipher_name, key_size)
    print("The key has been established")

    print("Initializing cryptosystem")
    crypto = cipher.new(key, cipher.MODE_CBC, iv)
    hashing = HMAC.new(key, digestmod=SHA256)
    print("All systems ready")

    while True:
        msg_in = conn.recv(4096)
        if len(msg_in) < 1:
            conn.close()
            break
        # print(msg_in)
        # msg_inn = msg_in.decode('UTF-8')
        # if urlfind.bol(msg_inn):
        #     print("ouch")
        #
        # else:

        msg, hmac = read_message(msg_in, crypto)
        validate_hmac(msg_in, hmac, hashing)
        print(f"Received: {msg}")
        msg_out = f"Server says: {msg[::-1]}"
        # print(type(msg_out))
        # print(type(msg_out.encode()))
        conn.send(msg_out.encode())


if __name__ == "__main__":
    main()
