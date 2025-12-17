import os
import io
import uuid
from flask import Flask, render_template, request, send_file, jsonify, flash, redirect, url_for
from cryptography.fernet import Fernet
import qrcode

# ---------------- CONFIG ----------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "qrappsecret")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.path.join(BASE_DIR, "secret.key")

# ---------------- Key utilities ----------------
def generate_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    return load_key()

def load_key():
    if not os.path.exists(KEY_FILE):
        return generate_key()
    with open(KEY_FILE, "rb") as f:
        return f.read()

# ---------------- Encryption / Decryption ----------------
def encrypt_text(plain_text: str) -> str:
    key = load_key()
    f = Fernet(key)
    token = f.encrypt(plain_text.encode("utf-8"))
    return token.decode("utf-8")

def decrypt_token(token_str: str) -> str:
    key = load_key()
    f = Fernet(key)
    decrypted = f.decrypt(token_str.encode("utf-8"))
    return decrypted.decode("utf-8")

# ---------------- QR generation ----------------
def qrcode_image_from_text(text: str) -> bytes:
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_Q)
    qr.add_data(text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf.read()

# ---------------- Routes ----------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/generate-key", methods=["POST"])
def api_generate_key():
    generate_key()
    return jsonify({"status": "ok", "message": "Key generated (or already exists)."})

@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    data = request.get_json(silent=True)
    if not data or "message" not in data:
        return jsonify({"error": "Missing 'message' in JSON body."}), 400
    message = data["message"]
    token = encrypt_text(message)
    img_bytes = qrcode_image_from_text(token)
    import base64
    data_url = "data:image/png;base64," + base64.b64encode(img_bytes).decode("ascii")
    return jsonify({"token": token, "qr_data_url": data_url})

@app.route("/api/encrypt-download", methods=["POST"])
def api_encrypt_download():
    message = request.form.get("message")
    if not message:
        flash("Please provide a message to encrypt.")
        return redirect(url_for("index"))
    token = encrypt_text(message)
    img_bytes = qrcode_image_from_text(token)
    return send_file(io.BytesIO(img_bytes), mimetype="image/png",
                     as_attachment=True, download_name=f"qr_encrypted_{uuid.uuid4().hex}.png")

@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    # Only accept JSON token string
    json_data = request.get_json(silent=True)
    if json_data and "token" in json_data:
        token = json_data["token"]
        try:
            plaintext = decrypt_token(token)
            return jsonify({"plaintext": plaintext})
        except Exception as e:
            return jsonify({"error": f"Decryption failed: {str(e)}"}), 400
    return jsonify({"error": "Only token string decryption is supported on Windows."}), 400

# ---------------- Run ----------------
if __name__ == "__main__":
    generate_key()
    app.run(debug=True)
