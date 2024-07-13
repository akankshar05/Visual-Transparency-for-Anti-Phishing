from flask import Flask, render_template, make_response
import json

app = Flask(__name__)


@app.route('/')
def index():
    with open('index.html', 'rb') as file:
        html_content = file.read().decode('utf-8')
    print(type(html_content))

    response = make_response(html_content)
    file_path = 'pt_header.json'
    with open(file_path, 'r') as file:
        json_data = file.read()
    data = json.loads(json_data)
    header_value = data.get('header', '')

    response.headers['pt-header'] = header_value
    response.headers['url'] = 'http://127.0.0.1:5006/'

    return response


if __name__ == '__main__':
    app.run(debug=True, port=5006)
