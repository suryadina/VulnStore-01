# Intentionally Vulnerable Web Application

This is an intentionally vulnerable web application created for web penetration testing practice and interview purposes. It is designed to help assess a candidate's web security knowledge and penetration testing skills.

**WARNING: This application contains deliberate security vulnerabilities. DO NOT deploy it on a production server or expose it to the internet.**

## Features

- User registration and login with TOTP MFA
- Product catalog and purchasing system
- User profiles
- Company profile with comments
- Admin functionality

## Vulnerabilities

This application intentionally includes several security vulnerabilities:

1. SQL Injection in the product catalog
2. MFA Bypass via an API endpoint
3. IDOR (Insecure Direct Object References) in user profiles
4. Logic error in payment processing
5. Stored XSS in company comments

## Setup

1. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Run the application:
   ```
   python app.py
   ```

3. Access the application at `http://localhost:62292`

## Usage

1. Register a new user account
2. Set up TOTP using an authenticator app
3. Log in with your credentials and TOTP code
4. Explore the application and try to find the vulnerabilities

## Admin Access

To make a user an admin, you need to:
1. Register at least one user
2. Find the admin path printed in the console when starting the app (`Admin path: /admin/[random-string]`)
3. Promote a user to admin through the admin panel

## Disclaimer

This application is provided for educational purposes only. The creator takes no responsibility for any misuse or damage caused by this application. Use at your own risk.