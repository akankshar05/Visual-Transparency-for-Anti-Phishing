# import requests
# # from bs4 import BeautifulSoup
# # from flask import Flask
# import requests
# import json
# import base64
# import struct
# from cryptography.hazmat.primitives import serialization, hashes
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.backends import default_backend
# import base64
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import rsa, padding
# from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, PublicFormat
# import hashlib


# # #######################################################################
# def check_header_valid_or_not(spt_header):

#     def pack_data(version, timestamp):
#         return struct.pack('!BI', version, timestamp)

#     data = [{"log_id":"uurdL9xX/sRXpamyMbgMQ4bj45pLGi4bYxzDb5N0el8=",
#     "pub_key":"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt5icORTWWHU88j+V91nA5cCPMEWj3qHi9czcgVKmid/2G5rCMU4oXq1QGbbNy00UbOLEZRU87Br+lTkyTWlLvO8MZt2uI8AWjrfzHpVfUG8eSiSoy12DLYXq3WDJlGsd6R40OUctlQWiHC4w2mBcPgwbgxhao8oJdgh3GuScrEefrYWroP8cDAY6CLFVesTjFat71OlHlVPoNzPQkV7+nWg0i0gwpPuhJTnBrtixOwVAUk5HYUL4e+OX2UnpiC6w+ixEpa2Y9QHm5RT1xMggx+iSTSYMADWFDzIDeHjRoLgxChu+CFEyzZkqduLACrYovfijhHDQntsT3LrPgVj1tQIDAQAB" },
# {"log_id":"dbhde",
# "pub_key":"fdwffrfrfr"}]


#     decoded_data = base64.b64decode(spt_header)
#     version = int.from_bytes(decoded_data[:1], byteorder='little')
#     timestamp = int.from_bytes(decoded_data[1:5], byteorder='little')
#     log_id_bytes=decoded_data[5:37]
#     signature = decoded_data[37:]
#     print(timestamp)
#     obtained_log_id= base64.b64encode(log_id_bytes).decode()
#     bool_found=False
#     index=0
#     for i in range(len(data)):
#         if obtained_log_id == data[i]["log_id"]:
#             bool_found=True
#             index=i
#     print(index)
#     if not bool_found:
#         return False

#     if bool_found:
#         encode_pub_key= data[index]["pub_key"]
#         der_key_obtained = base64.b64decode(encode_pub_key)
#         public_key_obtained = serialization.load_der_public_key(der_key_obtained, backend = default_backend())
#         data_obtained = pack_data(version, timestamp) 

#         try:
#             public_key_obtained.verify(
#                 signature,
#                 data_obtained,
#                 padding.PSS(
#                     mgf=padding.MGF1(hashes.SHA256()),
#                     salt_length=padding.PSS.MAX_LENGTH
#                 ),
#                 hashes.SHA256()
#             )
#             return True
#         except Exception as e:
#             return False
# ###################################################################################################
        


# from flask import Flask, request, jsonify

# app = Flask(__name__)

# @app.route('/process_data', methods=['POST'])
# def process_data():
#     data = request.json  
#     for my_dict in data:
#         if(my_dict['name']== 'pt-header'):
#             pt_header = my_dict['value']
#     print(pt_header)

#     response_data = check_header_valid_or_not(pt_header)
#     return jsonify(response_data)

# # pt_header = "AVYp22W66t0v3Ff+xFelqbIxuAxDhuPjmksaLhtjHMNvk3R6X5DE8MHQSpwsCzyzD1jItUqcg3SwsBHnOoSLNXNDKREl483mclj23tYhFSlZ6NRGAAZxT9ofP6eaPzFP7Echw0jMpiKjw7xEf2gLKM68ik2OT5YxON7ogGlx7kb/Iy67MlevayfeXQR1/TnhSn+77KMrYXo/a8wzEsOYiBB7aGiZflBLuiIoSRmKeTAybr1qiHsUFfByrjMwh1JSBtNmtTCcxHBmVlkTeHb37Y1s9sm4QCz2xs6G8cWjJGEXt8Wgsl4wvyXDZdvG7Q9BQw9UTwC4rlAv+ckwVmYnFx5SSQedJfaMwT83twRYMuyUt8gvFWzrLskTkfIeJO4b0FhmJ+4="


# # @app.route('/upload', methods=['POST'])
# # def upload_screenshot():
# #     if request.method == 'POST':
# #         data = request.get_json()
# #         screenshot_url = data.get('screenshotUrl')

# #         # Process the screenshot URL (save it, analyze it, etc.)
# #         # In this example, let's just print it
# #         print("Received screenshot URL:", screenshot_url)

# #         return jsonify({'message': 'Screenshot received successfully'}), 200


# if __name__ == '__main__':
#     app.run(port=5003)  # Run the server on port 5000



import requests
# from bs4 import BeautifulSoup
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


# #######################################################################
# def check_header_valid_or_not(spt_header, url ,content):
#     # if()
#     print("$$$$$$$$$$$")
#     content= "<!DOCTYPE html>\n" + content

#     print(spt_header)
#     print(url)
#     non_empty_lines = [line for line in content.splitlines() if line.strip()]

# # Join the non-empty lines back together
#     result = '\n'.join(non_empty_lines)

#     print(result)
#     # print("$$$$$$$$$$$$")
#     # content = content.decode('utf-8')
#     def pack_data(version, timestamp,hashed_result, hashed_result2 ):
#         format_string = '!BI64s 64s'
#         return struct.pack(format_string, version, timestamp, hashed_result.encode('utf-8'), hashed_result2.encode('utf-8'))
    
#     def hash_text(text):
#         text = text.lower()
#         text = text.replace(
#             " ", "").replace("\n", "").replace("\t", "")
#         print(text)
#         sha256_hash = hashlib.sha256()
#         sha256_hash.update(text.encode('utf-8'))
#         hashed_text = sha256_hash.hexdigest()
#         return hashed_text

#     file_path = 'logs.json'
#     with open(file_path, 'r') as file:
#         json_data = file.read()
#     data = json.loads(json_data)

#     hashed_result = hash_text(url)
#     content = content.lower()
#     hashed_result2 = hash_text(content)

#     decoded_data = base64.b64decode(spt_header)
#     # decoded_data = decoded_data.lower()

#     version = int.from_bytes(decoded_data[:1], byteorder='little')
#     timestamp = int.from_bytes(decoded_data[1:5], byteorder='little')
#     log_id_bytes = decoded_data[5:37]
#     signature = decoded_data[37:]
#     obtained_log_id = base64.b64encode(log_id_bytes).decode()
#     bool_found = False
#     index = 0
#     for i in range(len(data)):
#         if obtained_log_id == data[i]["log_id"]:
#             bool_found = True
#             index = i

#     if not bool_found:
#         return False

#     if bool_found:
#         encode_pub_key = data[index]["pub_key"]

#         der_key_obtained = base64.b64decode(encode_pub_key)
#         public_key_obtained = serialization.load_der_public_key(
#             der_key_obtained, backend=default_backend())
#         data_obtained = pack_data(
#             version, timestamp, hashed_result, hashed_result2) 
#         try:
#             public_key_obtained.verify(
#                 signature,
#                 data_obtained,
#                 padding.PSS(
#                     mgf=padding.MGF1(hashes.SHA256()),
#                     salt_length=padding.PSS.MAX_LENGTH
#                 ),
#                 hashes.SHA256()
#             )
#             return True
#         except Exception as e:
#             return False
# ##################################################################################################

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


from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/process_data', methods=['POST'])
# def process_data():
def process_data():
    # server_url = 'http://127.0.0.1:5001/'
    # response = requests.get(server_url)


    data = request.json  
    # print(data)

    headers = data.get('headers', {})
    entireDOM = data.get('entireDOM', '')

    # print(headers)
    # print("************")
    # print(entireDOM)
    # print("************")
    check_heaaader=False
    for my_dict in headers:
        if(my_dict['name']== 'pt-header'):
            check_heaaader=True
            pt_header = my_dict['value']
        if(my_dict['name']== 'url'):
            url = my_dict['value']
    # print(pt_header)
    if not check_heaaader:
        a={"msg":"Header not present"}
        return jsonify("Header not present")
    # pt_header = "AVYp22W66t0v3Ff+xFelqbIxuAxDhuPjmksaLhtjHMNvk3R6X5DE8MHQSpwsCzyzD1jItUqcg3SwsBHnOoSLNXNDKREl483mclj23tYhFSlZ6NRGAAZxT9ofP6eaPzFP7Echw0jMpiKjw7xEf2gLKM68ik2OT5YxON7ogGlx7kb/Iy67MlevayfeXQR1/TnhSn+77KMrYXo/a8wzEsOYiBB7aGiZflBLuiIoSRmKeTAybr1qiHsUFfByrjMwh1JSBtNmtTCcxHBmVlkTeHb37Y1s9sm4QCz2xs6G8cWjJGEXt8Wgsl4wvyXDZdvG7Q9BQw9UTwC4rlAv+ckwVmYnFx5SSQedJfaMwT83twRYMuyUt8gvFWzrLskTkfIeJO4b0FhmJ+4="
    # entireDOM_lower = entireDOM.lower()
    print("hello")
    # print(pt_header, url, entireDOM)
    try:
        response_data = check_header_valid_or_not(pt_header, url, entireDOM)
        return jsonify(response_data)
    except:
        print("header not defined")
        return jsonify("header not present")


    # content = response.content
    # pt_header = response.headers.get('pt-header', '')
    # url= response.headers.get('url', '')

    # if pt_header and url and check_header_valid_or_not(pt_header, url, content):
    #     print("signature is valid")
    # else:
    #     print("not valid")

    # soup = BeautifulSoup(content, 'html.parser')
    # body_content = soup.body if soup.body else soup
    # return f'<h2>Received Page:</h2>{body_content}<br><br><h3>Custom Header: {pt_header}'

if __name__ == '__main__':
    app.run(port = 5003)
    # get_page()
