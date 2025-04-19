from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from PIL import Image
from cryptography.fernet import Fernet
import io
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ===== Encryption Key Setup =====
key = Fernet.generate_key()
cipher = Fernet(key)

# ===== Allowed File Types =====
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ===== Message Encryption =====
def encrypt_message(message):
    return cipher.encrypt(message.encode()).decode()

def decrypt_message(token):
    return cipher.decrypt(token.encode()).decode()

# ===== Capacity Check =====
def check_capacity(image, message, bits_per_channel=1):
    total_bits = image.width * image.height * 3 * bits_per_channel
    return len(message) * 8 + 8 <= total_bits

# ===== Encode Message =====
def encode_image(image, message, bits_per_channel=1):
    img = image.convert('RGB')
    pixels = img.load()

    message += '\xFE'
    binary = ''.join(format(ord(c), '08b') for c in message)
    data_index = 0

    for y in range(img.height):
        for x in range(img.width):
            if data_index >= len(binary):
                break
            r, g, b = pixels[x, y]
            rgb = [r, g, b]
            for i in range(3):
                for bit in range(bits_per_channel):
                    if data_index >= len(binary):
                        break
                    rgb[i] = (rgb[i] & ~(1 << bit)) | (int(binary[data_index]) << bit)
                    data_index += 1
            pixels[x, y] = tuple(rgb)
        if data_index >= len(binary):
            break

    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    return buffer

# ===== Decode Message =====
def decode_image(image, bits_per_channel=1):
    img = image.convert('RGB')
    pixels = img.load()

    bits = ""
    for y in range(img.height):
        for x in range(img.width):
            r, g, b = pixels[x, y]
            for value in (r, g, b):
                for bit in range(bits_per_channel):
                    bits += str((value >> bit) & 1)

    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) < 8:
            break
        char = chr(int(byte, 2))
        if char == '\xFE':
            break
        chars.append(char)

    return ''.join(chars)

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        mode = request.form['mode']
        image = request.files['image']
        bit_depth = int(request.form.get('bitdepth', 1))

        if not allowed_file(image.filename):
            flash("Unsupported file format.")
            return redirect(url_for('index'))

        img = Image.open(image)

        if mode == 'encode':
            if 'textfile' in request.files and request.files['textfile'].filename:
                message = request.files['textfile'].read().decode()
            else:
                message = request.form['message']

            if not check_capacity(img, message, bit_depth):
                flash("Message is too large for this image and bit depth.")
                return redirect(url_for('index'))

            encrypted_message = encrypt_message(message)
            encoded = encode_image(img, encrypted_message, bit_depth)
            return send_file(encoded, mimetype='image/png', as_attachment=True, download_name="stego.png")

        elif mode == 'decode':
            extracted = decode_image(img, bit_depth)
            try:
                result = decrypt_message(extracted)
            except:
                result = "Failed to decrypt message. It may not be encrypted or may be corrupted."

    return render_template('index.html', result=result, key=key.decode())

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
