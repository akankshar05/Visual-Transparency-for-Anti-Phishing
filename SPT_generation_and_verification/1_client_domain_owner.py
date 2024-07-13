import requests
import json
import os

######################################################


def save_the_header(file_path, new_header_value):
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            data = json.load(file)
        data['header'] = new_header_value
        with open(file_path, 'w') as file:
            json.dump(data, file, indent=2)
    else:
        new_data = {'header': new_header_value}
        with open(file_path, 'w') as file:
            json.dump(new_data, file, indent=2)
########################################################


url = 'http://127.0.0.1:5000/process_url'

file_paths = ['index.html']

files = {}
for file_path in file_paths:
    with open(file_path, 'rb') as file:
        a = file.read().decode('utf-8')
        files[file_path] = a
print(type(files["index.html"]))

payload = {
    'URL': 'http://127.0.0.1:5006/',
    'files': files
}
print(payload)
headers = {'Content-Type': 'application/json'}
response = requests.post(url, json=payload, headers=headers)

if response.status_code == 200:
    result = response.json()
    status= result.get('status')
    print(status)
    if not status:
        print("can't be logged")
    else:
        print()
        print("Page successfullly logged!")
        print()
        spt_header = result.get('spt_header')

        print(f'SPT_header: {spt_header}')
        print()
        save_the_header("pt_header.json", spt_header)
else:
    print(f'Error: {response.status_code}, {response.json()}')
