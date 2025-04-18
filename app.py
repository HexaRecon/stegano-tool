from flask import Flask, render_template, request, send_file
from PIL import Image
import io
import os

app = Flask(__name__)

# Encode message into image
def encode_image(image, message):
    img = image.convert('RGB')
    pixels = img.load()

    binary = ''.join(format(ord(c), '08b') for c in message) + '1111111111111110'  # EOF marker
    data_index = 0

    for y in range(img.height):
        for x in range(img.width):
            if data_index >= len(binary):
                break
            r, g, b = pixels[x, y]
            r = (r & ~1) | int(binary[data_index])
            data_index += 1
            if data_index < len(binary):
                g = (g & ~1) | int(binary[data_index])
                data_index += 1
            if data_index < len(binary):
                b = (b & ~1) | int(binary[data_index])
                data_index += 1
            pixels[x, y] = (r, g, b)
        if data_index >= len(binary):
            break

    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    return buffer

# Decode message from image
def decode_image(image):
    img = image.convert('RGB')
    pixels = img.load()

    bits = ""
    for y in range(img.height):
        for x in range(img.width):
            r, g, b = pixels[x, y]
            bits += str(r & 1)
            bits += str(g & 1)
            bits += str(b & 1)

    chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)]
    msg = ''.join(chars)
    return msg.split('\xFE')[0]  # Cut off at EOF marker

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        mode = request.form['mode']
        image = request.files['image']
        img = Image.open(image)

        if mode == 'encode':
            message = request.form['message']
            encoded = encode_image(img, message)
            return send_file(encoded, mimetype='image/png', as_attachment=True, download_name="stego.png")

        elif mode == 'decode':
            result = decode_image(img)

    return render_template('index.html', result=result)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
