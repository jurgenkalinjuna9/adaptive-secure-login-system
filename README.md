# Adaptive Secure Login System

## Overview

This repository contains the prototype developed for my MSc Cybersecurity dissertation at Aston University.

The Adaptive Secure Login System is a Flask and MySQL-based authentication prototype designed to demonstrate how contextual risk indicators can be incorporated into the login process.

Unlike a conventional static login system that relies primarily on username and password verification, the prototype evaluates additional contextual information and adapts the authentication response according to the calculated risk.

## Project Objectives

The prototype was developed to:

- implement a conventional username and password authentication baseline;
- detect selected authentication risk indicators;
- calculate a combined risk score;
- classify authentication attempts according to risk;
- apply different authentication responses based on the identified risk;
- record authentication events and response times for evaluation.

## Risk Indicators

The adaptive authentication system evaluates three Key Risk Indicators (KRIs).

### KR1 - Repeated Failed Login Attempts

The system monitors consecutive failed authentication attempts.

Repeated failures increase authentication risk and can result in a temporary restriction when the configured threshold is reached.

### KR2 - Unknown or New Device

A browser device identifier is used to determine whether the device has previously been trusted for the user.

A new or unknown device contributes additional risk to the authentication attempt.

The device identifier is a prototype browser-based identifier and should not be interpreted as hardware-level device attestation.

### KR3 - IP Address Change

The system compares the current client IP address against IP addresses previously trusted for the user.

An unfamiliar IP address contributes additional authentication risk.

Because the prototype was evaluated in a local development environment, controlled IP variation can be simulated during testing.

## Risk Classification

The combined risk score is classified using the following thresholds:

| Risk Score | Risk Level |
|------------|------------|
| 0-2        | Low        |
| 3-4        | Medium     |
| 5+         | High       |

A dedicated repeated-failure rule is also implemented so that five or more consecutive failed login attempts can trigger a temporary restriction.

## Adaptive Authentication Responses

The system responds according to the assessed authentication risk:

| Risk Level | Adaptive Response |
|------------|-------------------|
| Low        | Normal login      |
| Medium     | Step-up verification |
| High       | Temporary restriction |

The step-up verification mechanism is implemented as a prototype confirmation stage. It is not intended to represent production multi-factor authentication.

## Main Features

- User registration
- Password hashing
- Username and password authentication
- Session-based access control
- Login attempt logging
- Consecutive failed-login detection
- Trusted device detection
- Trusted IP detection
- Combined risk scoring
- Low, Medium and High risk classification
- Step-up verification
- Temporary authentication restriction
- Authentication response-time recording

## Technology Stack

- Python
- Flask
- MySQL
- HTML
- CSS
- JavaScript
- Werkzeug
- mysql-connector-python
- python-dotenv

## Database Structure

The prototype uses four primary MySQL tables:

- `users` - stores registered user account information and password hashes;
- `login_attempts` - records authentication attempts, contextual information, risk information, adaptive actions and response times;
- `trusted_devices` - stores device identifiers previously trusted for registered users;
- `trusted_ips` - stores IP addresses previously trusted for registered users.

The relationships between these tables allow authentication events, trusted devices and trusted IP addresses to be associated with registered users.

The `login_attempts.user_id` field can also remain null when an authentication attempt uses a username that does not correspond to a registered account. This allows unsuccessful attempts involving unknown usernames to be recorded.

## Project Structure

```text
AdaptiveLogin/
│
├── static/
├── templates/
├── app.py
├── database.py
├── schema.sql
├── requirements.txt
├── .gitignore
└── README.md
```

The local `.env` file, Python virtual environment (`venv`) and Python cache files are intentionally excluded from version control.

## Installation

### 1. Clone the Repository

Clone the project from GitHub and move into the project directory:

```bash
git clone https://github.com/jurgenkalinjuna9/adaptive-secure-login-system.git
cd adaptive-secure-login-system
```

> Note: Access to the repository is required if it remains private.

### 2. Create a Python Virtual Environment

Create an isolated Python environment:

```bash
python -m venv venv
```

On Windows, activate it using:

```bash
venv\Scripts\activate
```

### 3. Install Dependencies

Install the required Python packages:

```bash
pip install -r requirements.txt
```

The `requirements.txt` file contains the Python dependencies used by the prototype.

### 4. Configure MySQL

MySQL Server must be installed and running before starting the application.

Create a MySQL database named:

```text
adaptive_login
```

The prototype uses the following tables:

- `users`
- `login_attempts`
- `trusted_devices`
- `trusted_ips`

The included `schema.sql` file defines the database tables and their relationships. Execute this SQL script against the `adaptive_login` database before running the application.

### 5. Configure Environment Variables

Create a local `.env` file in the project root.

Add the following variables using your own values:

```text
MYSQL_PASSWORD=your_mysql_password
FLASK_SECRET_KEY=your_flask_secret_key
```

The MySQL password must correspond to the local MySQL configuration.

The Flask secret key should be a securely generated random value and should not be shared.

Do not commit the `.env` file to version control.

### 6. Run the Application

Start the Flask application:

```bash
python app.py
```

The Flask development server will display the local address in the terminal. Open this address in a web browser to access the prototype.

## Testing

The prototype was evaluated using controlled authentication scenarios including:

- successful normal authentication;
- incorrect credentials;
- repeated failed login attempts;
- temporary restriction following repeated failures;
- new device detection;
- trusted device recognition;
- unfamiliar IP detection;
- trusted IP recognition;
- combined risk escalation;
- medium-risk step-up verification;
- unauthorised dashboard access;
- logout and session invalidation;
- SQL injection-style input testing;
- authentication response-time measurement.

Testing was conducted in a controlled local environment.

The security testing focused on the authentication behaviours required for the research prototype. SQL injection-style input testing was used to check that selected malicious input did not bypass authentication or cause an application failure; this should not be interpreted as proof of complete SQL injection immunity.

## Prototype Limitations

This system is a research prototype and is not intended for production deployment.

Notable limitations include:

- local Flask development deployment;
- browser-based device identification rather than hardware-backed device attestation;
- controlled IP simulation for local network-variation testing;
- prototype step-up confirmation rather than production multi-factor authentication;
- a short temporary restriction period configured to support repeatable testing.

A production implementation would require additional controls such as HTTPS, secure production session configuration, robust MFA or passkeys, stronger device identification, production infrastructure and additional security monitoring.

## Dissertation Context

This repository supports an MSc Cybersecurity dissertation investigating adaptive authentication and the use of contextual risk indicators to modify login security decisions.

The implementation focuses specifically on three risk indicators:

1. repeated failed login attempts;
2. unknown or new devices;
3. IP address changes.

The prototype provides a controlled environment for comparing conventional static authentication behaviour with adaptive risk-based authentication.