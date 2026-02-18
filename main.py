from flask import Flask, render_template, request, redirect, url_for, session, flash
from decrypt_and_load_questions import decrypt_exam_file
from email.message import EmailMessage
import random, smtplib, time, traceback, re, string, os
import mysql.connector
from datetime import datetime


app = Flask(__name__)
app.secret_key = 'Studentsecretkey'
otp_store = {}

# ---------------- disable cache ----------------
@app.after_request
def disable_cache(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# ---------------- helpers ----------------
def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        port=3306,
        user='root',
        password='',
        database='secure_exam'
    )

def generate_alphanumeric_otp(length=6):
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choices(chars, k=length))

# ---------------- send otp ----------------
def send_otp_email(receiver_email, otp):
    sender_email = "your mail id"
    app_password = "your app password"

    msg = EmailMessage()
    msg.set_content(f"Your OTP for login is: {otp}")
    msg['Subject'] = 'OTP Verification - Secure Exam Login'
    msg['From'] = sender_email
    msg['To'] = receiver_email

    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(sender_email, app_password)
        server.send_message(msg)
        server.quit()
    except Exception as e:
        print("OTP send error:", e)
        traceback.print_exc()

# ---------------- attempt helpers ----------------
def count_attempts_for_subject(email, subject):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM student_results WHERE email=%s AND subject=%s",
            (email, subject)
        )
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        return row[0] if row else 0
    except Exception as e:
        print("DB error:", e)
        return 0

def insert_result_to_db(name, email, reg_no, subject, score, percentage, time_taken_sec, tab_switches, attempt_count):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO student_results
            (name, email, reg_no, subject, score, percentage, time_taken_sec, tab_switches, attempt_count)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (name, email, reg_no, subject, score, percentage, time_taken_sec, tab_switches, attempt_count))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print("Insert error:", e)
        traceback.print_exc()

# ---------------- routes ----------------
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        session.clear()
        name = request.form.get('name','').strip()
        reg_no = request.form.get('reg_no','').strip()
        email = request.form.get('email','').strip()

        if not name or not reg_no or not email:
            flash("All fields required")
            return redirect(url_for('login'))

        if not is_valid_email(email):
            flash("Invalid email")
            return redirect(url_for('login'))

        otp = generate_alphanumeric_otp()
        send_otp_email(email, otp)
        otp_store[email] = otp

        session['email'] = email
        session['name'] = name
        session['reg_no'] = reg_no

        return redirect(url_for('verify_otp'))

    return render_template('login.html')

@app.route('/verify_otp', methods=['GET','POST'])
def verify_otp():
    if request.method == 'POST':
        entered = request.form.get('otp','').upper()
        email = session.get('email')

        if not email or otp_store.get(email) != entered:
            flash("Invalid OTP")
            return redirect(url_for('verify_otp'))

        return redirect(url_for('choose_exam'))

    return render_template('verify_otp.html')

@app.route('/choose_exam', methods=['GET','POST'])
def choose_exam():
    if 'email' not in session:
        return redirect(url_for('login'))

    # Dictionary to hold metadata for known exams
    exam_meta = {
        'python': {'title': 'Python Programming', 'prof': 'Dr.Sumathi', 'image': 'python.jpg'},
        'network': {'title': 'Computer Networking', 'prof': 'Dr. Anurekha', 'image': 'network.jpg'},
        'ai': {'title': 'AI Fundamentals', 'prof': 'Dr. Poongothai', 'image': 'ai.jpg'},
        'cyber': {'title': 'Cyber Security', 'prof': 'Dr. Sudha', 'image': 'cyber.jpg'},
        'ds': {'title': 'Data Structures', 'prof': 'Dr. Sathiyakala', 'image': 'ds.jpg'}
    }

    # Automatically scan the 'encrypted' folder for available exams
    found_exams = []
    
    # Get candidate images (only jpgs)
    image_dir = os.path.join(app.root_path, 'static', 'images')
    all_jpgs = [f for f in os.listdir(image_dir) if f.lower().endswith('.jpg')] if os.path.exists(image_dir) else []
    
    # List of realistic professor names
    prof_names = [
        "Dr. Sanjeev Gupta", "Dr. Manindra Agrawal", "Dr. Raj Reddy", 
        "Dr. Sukumar Nandi", "Dr. Sudha Murthy", "Dr. Ajay Kumar", 
        "Dr. Vinod Bansal", "Dr. Anantha Chandrakasan", "Dr. K. Mani Chandy"
    ]
    
    if os.path.exists('encrypted'):
        for f in os.listdir('encrypted'):
            if f.startswith('encrypted_questions_') and f.endswith('.bin'):
                subject_id = f.replace('encrypted_questions_', '').replace('.bin', '')
                
                # Get meta or use defaults
                if subject_id in exam_meta:
                    meta = exam_meta[subject_id]
                else:
                    # Pick a consistent "random" image and professor based on the subject_id string
                    # This prevents the data from changing on every page refresh
                    subject_hash = sum(ord(c) for c in subject_id)
                    
                    img_index = subject_hash % len(all_jpgs) if all_jpgs else 0
                    random_image = all_jpgs[img_index] if all_jpgs else 'background.jpg'
                    
                    prof_index = subject_hash % len(prof_names)
                    random_prof = prof_names[prof_index]
                    
                    meta = {
                        'title': subject_id.replace('_', ' ').title(),
                        'prof': random_prof,
                        'image': random_image
                    }
                
                found_exams.append({
                    'id': subject_id,
                    'title': meta['title'],
                    'prof': meta['prof'],
                    'institute': 'GCE-ERODE',
                    'image': meta['image']
                })

    if request.method == 'POST':
        selected_exam = request.form.get('exam_choice')
        if not selected_exam:
            flash("Select an exam")
            return redirect(url_for('choose_exam'))

        attempts = count_attempts_for_subject(session['email'], selected_exam)
        if attempts >= 3:
            flash("Maximum attempts reached")
            return redirect(url_for('login'))

        session['selected_exam'] = selected_exam
        return redirect(url_for('dashboard'))

    return render_template('choose_exam.html', exams=found_exams)

@app.route('/dashboard')
def dashboard():
    if 'email' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/exam', methods=['GET', 'POST'])
def exam():
    print(f"[DEBUG] /exam route accessed. Method: {request.method}")
    if 'email' not in session or 'selected_exam' not in session:
        print(f"[DEBUG] Missing session data. Email: {'email' in session}, Selected Exam: {'selected_exam' in session}")
        flash("Session expired. Please login again.")
        return redirect(url_for('login'))

    exam_type = session['selected_exam']
    print(f"[DEBUG] Starting exam for subject: {exam_type}")

    aes_key_file = os.path.join(app.root_path, 'encrypted', f'encrypted_aes_key_{exam_type}.bin')
    encrypted_questions_file = os.path.join(app.root_path, 'encrypted', f'encrypted_questions_{exam_type}.bin')
    private_key_file = os.path.join(app.root_path, 'private_key.pem')

    print(f"[DEBUG] Loading files: {aes_key_file}, {encrypted_questions_file}")
    try:
        if not os.path.exists(aes_key_file): print(f"[DEBUG] MISSING: {aes_key_file}")
        if not os.path.exists(encrypted_questions_file): print(f"[DEBUG] MISSING: {encrypted_questions_file}")
        if not os.path.exists(private_key_file): print(f"[DEBUG] MISSING: {private_key_file}")
        
        questions = decrypt_exam_file(aes_key_file, encrypted_questions_file, private_key_file)
        print(f"[DEBUG] Successfully decrypted {len(questions)} questions")
    except Exception as e:
        print(f"[DEBUG] Decryption error: {e}")
        import traceback
        traceback.print_exc()
        flash(f"Failed to load exam: {e}")
        return redirect(url_for('choose_exam'))

    for i, q in enumerate(questions):
        q["id"] = i + 1
        random.shuffle(q["options"])
    random.shuffle(questions)

    session['exam_questions'] = [
        {"id": q["id"], "question": q["question"], "options": q["options"], "correct_answer": q["answer"]}
        for q in questions
    ]
    session['start_time'] = time.time()

    return render_template('exam.html', questions=session['exam_questions'])

@app.route('/submit_exam', methods=['POST'])
def submit_exam():
    if 'email' not in session or 'exam_questions' not in session:
        return redirect(url_for('login'))

    questions = session['exam_questions']
    correct = 0

    for q in questions:
        if request.form.get(f'q{q["id"]}') == q["correct_answer"]:
            correct += 1

    total = len(questions)
    percentage = round((correct / total) * 100, 2)
    time_taken = int(time.time() - session['start_time'])
    tab_switches = int(request.form.get('tab_switches', 0))

    subject = session['selected_exam']

    attempts = count_attempts_for_subject(session['email'], subject)
    insert_result_to_db(
        session['name'], session['email'], session['reg_no'],
        subject, correct, percentage,
        time_taken, tab_switches, attempts + 1
    )

    session['score_data'] = {
        "score": correct,
        "total": total,
        "percentage": percentage
    }

    # ✅ STORE SUBJECT FOR CERTIFICATE
    session['certificate_subject'] = subject

    # ✅ CLEANUP
    session.pop('exam_questions', None)
    session.pop('start_time', None)
    session.pop('selected_exam', None)

    return render_template('result.html', score=f"{correct} / {total}", percentage=percentage)
@app.route('/logout')
def logout():
    session.clear()   # 🔥 clears everything safely
    return redirect(url_for('login'))

@app.route('/download_certificate')
def download_certificate():
    if 'score_data' not in session:
        return redirect(url_for('login'))

    if session['score_data']['percentage'] < 50:
        flash("Minimum 50% required")
        return redirect(url_for('result_page'))

    print("CERT SUBJECT:", session.get('certificate_subject'))  # DEBUG

    return render_template(
        "certificate.html",
        current_date=datetime.now().strftime("%d %B %Y"),
        subject=session.get('certificate_subject', 'Subject')
    )

@app.route('/result')
def result_page():
    if 'score_data' not in session:
        return redirect(url_for('dashboard'))
    sd = session['score_data']
    return render_template('result.html', score=f"{sd['score']} / {sd['total']}", percentage=sd['percentage'])
    
# @app.route('/face_check')
# def face_check():
#     result = monitor_faces()
#     if result == "MULTIPLE":
#         return {"status": "violation"}, 403
#     return {"status": "ok"}


if __name__ == '__main__':
    app.run(debug=True)
