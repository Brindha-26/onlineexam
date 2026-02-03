from flask import Flask, render_template, request, redirect, session, flash
import mysql.connector
import os, json
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "adminsecretkey"

# ================== UPLOAD SETTINGS ==================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {"json"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# ================== DATABASE ==================

def get_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="secure_exam"
    )

# ================== ADMIN LOGIN ==================

@app.route("/", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM admin WHERE username=%s AND password=%s",
            (username, password)
        )
        admin = cursor.fetchone()
        cursor.close()
        db.close()

        if admin:
            session["admin"] = username
            return redirect("/dashboard")

        flash("❌ Invalid Login")

    return render_template("login.html")

# ================== DASHBOARD ==================

@app.route("/dashboard")
def dashboard():
    if "admin" not in session:
        return redirect("/")
    return render_template("dashboard.html")

# ================== ADD QUESTIONS ==================

@app.route("/addquestion", methods=["GET", "POST"])
def addquestion():
    if "admin" not in session:
        return redirect("/")

    if request.method == "POST":
        file = request.files.get("file")

        if not file or file.filename == "":
            flash("❌ No file selected")
            return redirect("/addquestion")

        if not allowed_file(file.filename):
            flash("❌ Only JSON files allowed")
            return redirect("/addquestion")

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        subject_name = os.path.splitext(filename)[0].capitalize()

        # ---------- LOAD JSON ----------
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            flash("❌ Invalid JSON file")
            print("JSON ERROR:", e)
            return redirect("/addquestion")

        # ---------- SUPPORT BOTH FORMATS ----------
        if isinstance(data, list):
            questions = data
        elif isinstance(data, dict) and "questions" in data:
            questions = data["questions"]
        else:
            flash("❌ Invalid JSON structure")
            return redirect("/addquestion")

        # Database insertion removed as per user request. 
        # Questions are now handled via the Automatic Encryption logic below.


        flash(
            f"✅ Subject '{subject_name}' uploaded | "
        )

        # ---------- TRIGGER AUTOMATIC ENCRYPTION ----------
        try:
            # We can import the logic from auto_encrypt or run it as a script
            # Since auto_encrypt.py is in the parent dir, we use a simple command call or shared logic
            # For now, let's call the encryption function logic
            from pathlib import Path
            import json
            from Crypto.Cipher import AES, PKCS1_OAEP
            from Crypto.PublicKey import RSA
            from Crypto.Random import get_random_bytes

            PARENT_DIR = Path(BASE_DIR).parent
            ENCRYPTED_DIR = PARENT_DIR / "encrypted"
            PUBLIC_KEY_PATH = PARENT_DIR / "public_key.pem"
            
            if PUBLIC_KEY_PATH.exists():
                recipient_key = RSA.import_key(open(PUBLIC_KEY_PATH).read())
                cipher_rsa = PKCS1_OAEP.new(recipient_key)
                
                subject_id = os.path.splitext(filename)[0].lower()
                data_bytes = json.dumps(data).encode('utf-8')
                aes_key = get_random_bytes(16)
                
                cipher_aes = AES.new(aes_key, AES.MODE_EAX)
                ciphertext, tag = cipher_aes.encrypt_and_digest(data_bytes)
                
                os.makedirs(ENCRYPTED_DIR, exist_ok=True)
                
                with open(ENCRYPTED_DIR / f"encrypted_questions_{subject_id}.bin", "wb") as f:
                    [f.write(x) for x in (cipher_aes.nonce, tag, ciphertext)]
                
                enc_aes_key = cipher_rsa.encrypt(aes_key)
                with open(ENCRYPTED_DIR / f"encrypted_aes_key_{subject_id}.bin", "wb") as f:
                    f.write(enc_aes_key)
                
                flash(f"✅ Auto-Encrypted: {subject_id}")
            else:
                flash("⚠️ Encryption failed: RSA keys missing in root.")

        except Exception as e:
            print("AUTO-ENCRYPT ERROR:", e)
            flash("⚠️ question uploaded but auto-encryption failed.")

        return redirect("/addquestion")

    return render_template("addquestion.html")

# ================== RESULTS ==================

@app.route("/results")
def results():
    if "admin" not in session:
        return redirect("/")

    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT name, subject, score, percentage, exam_date, reg_no
        FROM student_results
        ORDER BY subject ASC, exam_date DESC
    """)
    rows = cursor.fetchall()
    cursor.close()
    db.close()

    # Group by subject
    grouped_data = {}
    for row in rows:
        subj = row['subject']
        if subj not in grouped_data:
            grouped_data[subj] = []
        grouped_data[subj].append(row)

    return render_template("results.html", grouped_data=grouped_data)

# ================== LOGOUT ==================

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ================== RUN ==================

if __name__ == "__main__":
    app.run(debug=True, port=5001)
