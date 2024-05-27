# from flask import Flask, render_template, make_response
# import json
# app = Flask(__name__)

# @app.route('/')
# def index():

#     html_content =  """<!DOCTYPE html>
# <html lang="en">
#   <head>
#     <meta charset="UTF-8" />
#     <meta name="viewport" content="width=device-width, initial-scale=1.0" />
#     <title>Login Page</title>
#     <style>
#       body {
#         font-family: Arial, sans-serif;
#         background-color: #f4f4f4;
#         margin: 0;
#         padding: 0;
#         display: flex;
#         justify-content: center;
#         align-items: center;
#         height: 100vh;
#       }
#       form {
#         background-color: #fff;
#         padding: 20px;
#         border-radius: 5px;
#         box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
#       }
#       input[type="text"],
#       input[type="password"] {
#         width: 100%;
#         padding: 10px;
#         margin: 8px 0;
#         border: 1px solid #ccc;
#         border-radius: 4px;
#         box-sizing: border-box;
#       }
#       input[type="submit"] {
#         width: 100%;
#         background-color: #4caf50;
#         color: white;
#         padding: 14px 20px;
#         margin: 8px 0;
#         border: none;
#         border-radius: 4px;
#         cursor: pointer;
#       }
#       input[type="submit"]:hover {
#         background-color: #45a049;
#       }
#     </style>
#   </head>
#   <body>
#     <form action="#" method="post">
#       <h1>BTP-II</h1>
#       <h2>Login</h2>
#       <label for="username">Username:</label>
#       <input type="text" id="username" name="username" required />

#       <label for="password">Password:</label>
#       <input type="password" id="password" name="password" required />

#       <input type="submit" value="Login" />
#     </form>
#   </body>
# </html>"""


#     # html_content = '<h1>Welcome to MY PAGE</h1>'
#     response = make_response(html_content)

#     ########getting header##########################
#     file_path = 'pt_header.json'
#     with open(file_path, 'r') as file:
#         json_data = file.read()
#     data = json.loads(json_data)
#     header_value = data['header']
#     #################################################

#     # Add custom header 'pt-header'
#     response.headers['pt-header'] = header_value

#     return response

# if __name__ == '__main__':
#     app.run(debug=True, port=5001)




from flask import Flask, render_template, make_response
import json

app = Flask(__name__)

@app.route('/')
def index():
    with open('index.html', 'rb') as file:
        html_content = file.read().decode('utf-8')

    response = make_response(html_content)
    file_path = 'pt_header.json'
    with open(file_path, 'r') as file:
        json_data = file.read()
    data = json.loads(json_data)
    header_value = data.get('header', '')

    response.headers['pt-header'] = header_value
    response.headers['url'] = 'http://127.0.0.1:5001/'

    return response

if __name__ == '__main__':
    app.run(debug=True, port=5005)


######## This is a page going to be loaded on browser that gets rendered with pt_header, url added in their headers.