from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from pymongo import MongoClient

app = Flask(__name__)
CORS(app)  # Enable CORS
socketio = SocketIO(app, cors_allowed_origins="*")  # Allow WebSocket connections from any origin

# Generate encryption key (24 bytes for Triple DES)
key = get_random_bytes(24)
cipher = DES3.new(key, DES3.MODE_EAX)

# Connect to MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['chat_app']
users_collection = db['users']
messages_collection = db['messages']

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']
    user = users_collection.find_one({'username': username, 'password': password})
    if user:
        # Authentication successful, return token
        token = cipher.encrypt(username.encode()).decode()
        return jsonify({'token': token})
    else:
        return jsonify({'error': 'Invalid username or password'}), 401

@socketio.on('send_message')
def handle_message(data):
    token = data['token']
    message = data['message']
    decrypted_token = cipher.decrypt(token.encode()).decode()
    # Check if the token is valid
    if decrypted_token:
        # Encrypt message
        encrypted_message, tag = cipher.encrypt_and_digest(message.encode())
        messages_collection.insert_one({'username': decrypted_token, 'message': encrypted_message})
        emit('receive_message', {'encrypted_message': encrypted_message}, broadcast=True)
        return {'message': 'Message sent successfully'}
    else:
        return {'error': 'Invalid token'}, 401

if __name__ == '__main__':
    socketio.run(app)
