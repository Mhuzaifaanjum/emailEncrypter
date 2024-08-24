from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_mail import Mail, Message
from cryptography.fernet import Fernet
import os
import pickle
import base64

app = Flask(__name__)
app.secret_key = 'seCpFDPsjezl_KA6tQSMBZw5rpbcOmZVHd8crFqfdP8='

# Initialize Flask-Mail globally
mail = Mail()

# Function to generate a key and save it into a file
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

# Function to load the key from the current directory named `secret.key`
def load_key():
    return open("secret.key", "rb").read()

# Function to save user-generated custom key
def save_custom_key(user_key):
    with open("custom_secret.key", "wb") as key_file:
        key_file.write(user_key.encode())

# Function to save credentials
def save_credentials(email, password):
    credentials = {
        'email': email,
        'password': password
    }
    with open("credentials.pkl", "wb") as file:
        pickle.dump(credentials, file)

# Function to load saved credentials
def load_credentials():
    try:
        with open("credentials.pkl", "rb") as file:
            credentials = pickle.load(file)
            return credentials['email'], credentials['password']
    except FileNotFoundError:
        return None, None

# Function to encrypt a message
def encrypt_message(message):
    if os.path.exists("custom_secret.key"):
        key = open("custom_secret.key", "rb").read()
    else:
        key = load_key()
    encoded_message = message.encode()
    f = Fernet(key)
    encrypted_message = f.encrypt(encoded_message)
    return encrypted_message

# Function to decrypt a message using a provided key
def decrypt_message_with_key(encrypted_message, key):
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message)
    return decrypted_message.decode()

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        save_credentials(email, password)
        session['email'] = email
        session['password'] = password

        # Dynamically set the Flask-Mail configuration
        app.config['MAIL_USERNAME'] = email
        app.config['MAIL_PASSWORD'] = password
        app.config['MAIL_SERVER'] = 'smtp.gmail.com'
        app.config['MAIL_PORT'] = 587
        app.config['MAIL_USE_TLS'] = True
        app.config['MAIL_USE_SSL'] = False

        # Initialize Flask-Mail with updated config
        mail.init_app(app)

        return redirect(url_for('email'))

    return render_template('login.html')

@app.route('/generate_key', methods=['POST'])
def generate_key_route():
    user_key = Fernet.generate_key().decode()
    save_custom_key(user_key)
    flash(f'Generated Key: {user_key}', 'success')
    return redirect(url_for('email'))

@app.route('/email', methods=['GET', 'POST'])
def email():
    if request.method == 'POST':
        recipient = request.form['recipient']
        subject = request.form['subject']
        message = request.form['message']

        encrypted_message = encrypt_message(message)

        msg = Message(subject, sender=session.get('email'), recipients=[recipient])
        msg.body = base64.b64encode(encrypted_message).decode()  # Encode for email transmission
        try:
            mail.send(msg)
            flash('Email sent successfully!', 'success')
        except Exception as e:
            flash(f'Failed to send email: {e}', 'danger')

    return render_template('email.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    decrypted_message = None
    if request.method == 'POST':
        encrypted_message = request.form['encrypted_message']
        key = request.form['key']

        try:
            # Decode the base64 encoded encrypted message
            encrypted_message_bytes = base64.b64decode(encrypted_message)
            # Ensure the key is in bytes
            key_bytes = key.encode()
            # Decrypt the message using the provided key
            decrypted_message = decrypt_message_with_key(encrypted_message_bytes, key_bytes)
            flash('Message decrypted successfully!', 'success')
        except Exception as e:
            flash(f'Failed to decrypt message: {e}', 'danger')

    return render_template('decrypt.html', decrypted_message=decrypted_message)

# New route to handle AJAX requests for decryption
@app.route('/decrypt_message', methods=['POST'])
def decrypt_message():
    encrypted_message = request.form['encrypted_message']
    key = request.form['key']

    try:
        # Decode the base64 encoded encrypted message
        encrypted_message_bytes = base64.b64decode(encrypted_message)
        # Ensure the key is in bytes
        key_bytes = key.encode()
        # Decrypt the message using the provided key
        decrypted_message = decrypt_message_with_key(encrypted_message_bytes, key_bytes)
        return jsonify({'status': 'success', 'message': decrypted_message})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    if not os.path.exists("secret.key"):
        generate_key()
    app.run(debug=True)
