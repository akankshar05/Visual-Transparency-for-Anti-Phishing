from http.server import BaseHTTPRequestHandler, HTTPServer
import re
import base64
import time
import requests


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

def check_phishing_or_not():
    print("helllllooooooooo")

    import shutil
    # Example usage
    source_file = "./screenshot.png"
    destination_folder = '/home/ubn/Desktop/cnn_btp/VisualPhishNet/code/our_eval/screenshot'
    empty_directory(destination_folder)
    
    # Copy the file from source to destination
    shutil.copy(source_file, destination_folder)
    response = requests.get('http://localhost:6001/api/call_model')
    if response.status_code == 200:
        data = response.json()
        phishing= data["phishing"]
        return phishing
    
    return False


class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Set response status code
        self.send_response(200)
        # Set headers
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

        # Get content length
        content_length = int(self.headers['Content-Length'])
        # Read POST data (image data)
        image_data = self.rfile.read(content_length).decode('utf-8')

        # Extract base64 image data from the data URL
        match = re.search(r'data:image\/png;base64,(.*)', image_data)
        if match:
            image_base64 = match.group(1)

            # Decode base64 image data
            decoded_image = base64.b64decode(image_base64)

            # Save the decoded image data to a file
            with open('screenshot.png', 'wb') as f:
                f.write(decoded_image)
            is_phishing = check_phishing_or_not()  # Placeholder logic, replace with actual logic

            if is_phishing:
                response_message = 'phishing'
            else:
                response_message = 'not phishing'
            # Determine if the screenshot is phishing (replace this with your logic)
            # is_phishing = True  # Placeholder logic, replace with actual logic
            # # time.sleep(15)
            # if is_phishing:
            #     response_message = 'phishing'
            # else:
            #     response_message = 'not phishing'

            # Send response back to the client
            self.wfile.write(response_message.encode('utf-8'))
        else:
            # Send error response back to the client
            response_message = 'Error: Invalid image data format!'
            self.wfile.write(response_message.encode('utf-8'))

# Define server address and port
server_address = ('localhost', 8000)

# Create HTTP server
httpd = HTTPServer(server_address, RequestHandler)

# Start server
print('Server running on', server_address)
httpd.serve_forever()
