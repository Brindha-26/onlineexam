-- Database Setup for Online Secure Exam Project
-- This file contains the schema and queries for both the student app (main.py) and admin panel (adminpanel/app.py)

CREATE DATABASE IF NOT EXISTS secure_exam;
USE secure_exam;

-- Table for Admin Users
CREATE TABLE IF NOT EXISTS admin (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL
);

-- Table for Student Results
CREATE TABLE IF NOT EXISTS student_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    reg_no VARCHAR(255) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    score INT NOT NULL,
    percentage DECIMAL(5,2) NOT NULL,
    time_taken_sec INT NOT NULL,
    tab_switches INT DEFAULT 0,
    attempt_count INT DEFAULT 1,
    exam_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert a default admin account
-- You can change the credentials here
INSERT INTO admin (username, password) 
SELECT 'admin', 'admin123' 
WHERE NOT EXISTS (SELECT 1 FROM admin WHERE username = 'admin');

-- ---------------------------------------------------------
-- QUERIES USED IN THE PROJECT
-- ---------------------------------------------------------

-- 1. Check Previous Attempts (main.py)
-- SELECT COUNT(*) FROM student_results WHERE email=%s AND subject=%s;

-- 2. Save Exam Results (main.py)
-- INSERT INTO student_results (name, email, reg_no, subject, score, percentage, time_taken_sec, tab_switches, attempt_count) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s);

-- 3. Admin Login (adminpanel/app.py)
-- SELECT * FROM admin WHERE username=%s AND password=%s;

-- 4. View All Results (adminpanel/app.py)
-- SELECT name, subject, score, percentage, exam_date, reg_no FROM student_results ORDER BY subject ASC, exam_date DESC;
