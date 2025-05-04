# 🕵️‍♂️ Stegano Tool (Tkinter GUI)

A simple and user-friendly **steganography desktop application** built using **Python and Tkinter**. This tool allows you to **hide** secret messages inside PNG images and **extract** them later using **Least Significant Bit (LSB)** encoding.

## ✨ Features

- 🔐 Hide (encode) secret text inside images.
- 🔍 Extract (decode) hidden text from images.
- 🖼️ Supports `.png` images.
- 🧠 LSB (Least Significant Bit) steganography technique.
- 🖥️ Built with Tkinter — no web browser needed!
- 💡 Easy to use interface.

## 🖼️ GUI Preview
![image](https://github.com/user-attachments/assets/b23d4d99-1136-41b2-98fc-8f66ac577a4d)



## 🧰 Technologies Used

- Python 3
- Tkinter (for GUI)
- PIL / Pillow (for image processing)

## 📦 Installation

### 1. Clone the repository

```bash
git clone https://github.com/HexaRecon/stegano-tool.git
cd stegano-tool

2. Create a virtual environment (optional but recommended)

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

3. Install dependencies

pip install -r requirements.txt

4. Run the application

python stegano_tool.py

    Replace stegano_tool.py with your main Python file name if different.


🧠 How It Works
Encoding:

    Load a cover image (.png).

    Type your secret message.

    Click "Encode" and save the new stego image.

Decoding:

    Load a stego image.

    Click "Decode" to view the hidden message.

🤝 Contributing

Feel free to fork this repo, open issues, or submit pull requests. Contributions are welcome!
👨‍💻 Author

Made with ❤️ by HexaRecon
