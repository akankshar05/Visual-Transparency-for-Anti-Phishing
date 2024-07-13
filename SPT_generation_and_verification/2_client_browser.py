import requests
from bs4 import BeautifulSoup
from flask import Flask
import requests
import json
import base64
import struct
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, PublicFormat
import hashlib


#######################################################################
def check_header_valid_or_not(spt_header, url, content):
    url = "http://127.0.0.1:5006/"
    file_paths = ['index.html']
    files = {}

    for file_path in file_paths:
        with open(file_path, 'rb') as file:
            a = file.read().decode('utf-8')
            files[file_path] = a
    content = files['index.html']

    print(type(content))

    def pack_data(version, timestamp, hashed_result, hashed_result2):
        format_string = '!BI64s 64s'
        return struct.pack(format_string, version, timestamp, hashed_result.encode('utf-8'), hashed_result2.encode('utf-8'))

    def hash_text(text):

        text = text.lower()
        text = text.replace(
            " ", "").replace("\n", "").replace("\t", "")
        sha256_hash = hashlib.sha256()
        sha256_hash.update(text.encode('utf-8'))
        hashed_text = sha256_hash.hexdigest()
        return hashed_text

    file_path = 'logs.json'
    with open(file_path, 'r') as file:
        json_data = file.read()
    data = json.loads(json_data)

    hashed_result = hash_text(url)
    content = content.lower()
    hashed_result2 = hash_text(content)

    decoded_data = base64.b64decode(spt_header)
    version = int.from_bytes(decoded_data[:1], byteorder='little')
    timestamp = int.from_bytes(decoded_data[1:5], byteorder='little')
    log_id_bytes = decoded_data[5:37]
    signature = decoded_data[37:]
    obtained_log_id = base64.b64encode(log_id_bytes).decode()
    bool_found = False
    index = 0
    for i in range(len(data)):
        if obtained_log_id == data[i]["log_id"]:
            bool_found = True
            index = i

    if not bool_found:
        return False

    if bool_found:
        encode_pub_key = data[index]["pub_key"]

        der_key_obtained = base64.b64decode(encode_pub_key)
        public_key_obtained = serialization.load_der_public_key(
            der_key_obtained, backend=default_backend())
        data_obtained = pack_data(
            version, timestamp, hashed_result, hashed_result2)
        try:
            public_key_obtained.verify(
                signature,
                data_obtained,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            return False
###################################################################################################


app = Flask(__name__)


def get_page():
    server_url = 'http://127.0.0.1:5006/'
    response = requests.get(server_url)

    content = response.content
    content = content.decode('utf-8')
    print(type(content))
    pt_header = response.headers.get('pt-header', '')
    url = response.headers.get('url', '')

    if pt_header and url and check_header_valid_or_not(pt_header, url, content):
        print("signature is valid")
    else:
        print("not valid")

    soup = BeautifulSoup(content, 'html.parser')
    body_content = soup.body if soup.body else soup
    return f'<h2>Received Page:</h2>{body_content}<br><br><h3>Custom Header: {pt_header}'


if __name__ == '__main__':
    get_page()
