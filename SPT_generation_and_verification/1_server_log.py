from flask import Flask, request, jsonify
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import base64
import hashlib
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
import time
import hashlib

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
import requests


def get_body(text):
    soup = BeautifulSoup(text, 'html.parser')
    body_elements = soup.body
    print(body_elements)


def hash_text(text):
    text = text.lower()
    text = text.replace(
        " ", "").replace("\n", "").replace("\t", "")
    print(text)
    sha256_hash = hashlib.sha256()
    sha256_hash.update(text.encode('utf-8'))
    hashed_text = sha256_hash.hexdigest()
    return hashed_text

################ SPT generation#############################


def SPT_genration(url, files):
    def load_key_from_file(filename, key_type):
        with open(filename, 'rb') as file:
            key_str = file.read()
            if key_type == 'private':
                return serialization.load_pem_private_key(key_str, password=None, backend=default_backend())
            elif key_type == 'public':
                return serialization.load_pem_public_key(key_str, backend=default_backend())
            else:
                raise ValueError(
                    "Invalid key type. Use 'private' or 'public'.")
    private_key = load_key_from_file('private_key.pem', 'private')
    public_key = load_key_from_file('public_key.pem', 'public')

    hashed_result = hash_text(url)
    page = files['index.html']
    print(type(page))
    hashed_result2 = hash_text(page)

    # der_key = public_key.public_bytes(
    #     encoding=serialization.Encoding.DER,
    #     format=serialization.PublicFormat.SubjectPublicKeyInfo)
    # base64_key = base64.b64encode(der_key).decode()

    # def func_bytes_for_log_id(key):
    #     decoded_key = base64.b64decode(key)
    #     sha256_hash = hashlib.sha256(decoded_key).digest()
    #     return sha256_hash
    # bytes_for_log_id = func_bytes_for_log_id(base64_key)
    der_key = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    def func_bytes_for_log_id(der_key):
        sha256_hash = hashlib.sha256(der_key).digest()
        return sha256_hash

    bytes_for_log_id = func_bytes_for_log_id(der_key)

    def pack_data(version, timestamp, hashed_result, hashed_result2):
        format_string = '!BI64s 64s'
        return struct.pack(format_string, version, timestamp, hashed_result.encode('utf-8'), hashed_result2.encode('utf-8'))
    version = 1
    timestamp = int(time.time())
    data_to_sign = pack_data(version, timestamp, hashed_result, hashed_result2)
    signature = private_key.sign(
        data_to_sign,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    bytes_data = bytes([version, (timestamp & 0xFF), ((timestamp >> 8) & 0xFF), ((
        timestamp >> 16) & 0xFF), ((timestamp >> 24) & 0xFF)])
    final_data = bytes_data + bytes_for_log_id + signature
    # print(final_data)
    encoded_data = base64.b64encode(final_data)
    pt_header = encoded_data.decode('utf-8')
    print("pt_header is : ", pt_header)

    return pt_header


###########################################################

app = Flask(__name__)


def capture_screenshot(url, name):
    service = Service()
    options = webdriver.ChromeOptions()
    options.add_experimental_option('excludeSwitches', ['enable-logging'])

    driver = webdriver.Chrome(service=service, options=options)
    driver.set_window_size(1920, 1000)
    driver.get(url)
    driver.save_screenshot(name+".png")
    driver.quit()
    return

import os

def empty_directory(directory):
    if os.path.exists(directory):
        for file_name in os.listdir(directory):
            file_path = os.path.join(directory, file_name)
            if os.path.isfile(file_path):
                os.remove(file_path)
            elif os.path.isdir(file_path):
                empty_directory(file_path)
    else:
        print(f"The directory '{directory}' does not exist.")



def check_phishing_or_not(name):

    import shutil
    # Example usage
    source_file = './'+name+".png"
    destination_folder = '/home/ubn/Desktop/cnn_btp/VisualPhishNet/code/our_eval/screenshot'
    empty_directory(destination_folder)
    
    shutil.copy(source_file, destination_folder)
    response = requests.get('http://localhost:6001/api/call_model')
    if response.status_code == 200:
        data = response.json()
        phishing= data["phishing"]
        return phishing
    
    return False


def log_or_not(name, url, files):
    # print(name)
    # if check_phishing_or_not(name):
    #     return "CAN'T BE LOGGED : similar to other web pages"
    # else:
    return SPT_genration(url, files)


@app.route('/process_url', methods=['POST'])
def process_url():
    try:
        print(request)
        data = request.json
        print(data)
        url = data.get('URL')
        files = data.get('files')
        print(type(files['index.html']))
        print(len(files))
        if url:
            if files:
                print(url)
                domain = url.split('//')[1].split('/')[0]
                formatted_domain = domain.replace('.', '_')
                # capture_screenshot(url, formatted_domain)
                signed_page_timestamp = log_or_not(
                    formatted_domain, url, files)

                return jsonify({'status':1,'spt_header': signed_page_timestamp})
            else:
                return jsonify({'status':0,'error': 'files not provided'}), 400
        else:
            return jsonify({'status':0,'error': 'URL not provided'}), 400
    except Exception as e:
        return jsonify({'status':0,'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
