---
description: How to use the Online Secure Exam Admin Panel
---

# Admin Panel Workflow

The Admin Panel is a separate interface for educators to manage examinations and view student performance.

## 1. Accessing the Admin Panel
1. Start the admin server by running `python adminpanel/app.py`.
2. Open your browser and navigate to `http://localhost:5001`.
3. Log in with your admin credentials.

## 2. Managing Questions (Auto-Encryption)
// turbo
1. Prepare a JSON file containing exam questions (e.g., `mathematics.json`).
2. Navigate to the **Add Question** section.
3. Upload the JSON file.
4. The system will automatically:
   - Save the raw JSON to the `uploads/` folder.
   - Generate an AES key for the subject.
   - Encrypt the questions using the AES key.
   - Encrypt the AES key using the RSA Public Key (`public_key.pem`).
   - Save the encrypted files to the root `encrypted/` directory.

## 3. Monitoring Results
1. Navigate to the **Results** section.
2. View student scores, percentages, and number of tab switches (violations).
3. Use this data to verify the integrity of the student's exam attempt.

## 4. Security Highlights
- **No OpenCV Requirement**: The admin panel logic is independent of face monitoring.
- **Asymmetric Encryption**: Admin manages public/private keys to ensure only the secure exam environment can decrypt questions.
