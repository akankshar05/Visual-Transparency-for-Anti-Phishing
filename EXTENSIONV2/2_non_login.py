from flask import Flask, render_template, make_response
import json
app = Flask(__name__)

@app.route('/')
def index():

    html_content =  """<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <h1> HI! this is front page</h1>
</html>"""


    # html_content = '<h1>Welcome to MY PAGE</h1>'
    response = make_response(html_content)

    ########getting header##########################
    file_path = 'pt_header.json'
    with open(file_path, 'r') as file:
        json_data = file.read()
    data = json.loads(json_data)
    header_value = data['header']
    #################################################

    # Add custom header 'pt-header'
    response.headers['pt-header'] = header_value

    return response

if __name__ == '__main__':
    app.run(debug=True, port=5002)




