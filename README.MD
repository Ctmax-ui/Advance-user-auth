# User Authentication REST API

## Overview
This is a simple Node.js and Express-based REST API that provides user authentication features like user registration, login, and logout. The API is designed to be a scalable foundation for a complete authentication system and will later include support for Google OAuth, fingerprint, and passkey login. Currently, it supports traditional email/password-based authentication with JWT tokens for session management.

## Features
- **User Registration and Login** with secure password hashing using `bcrypt`.
- **JWT-Based Authentication**: Secure access with JWT access and refresh tokens.
- **Rate Limiting**: Protects routes from excessive requests.
- **Password Reset**: Sends a password reset link via email using `nodemailer`.
- **Cookie Management**: Uses HTTP cookies to manage session tokens.
- **MongoDB for Data Persistence**: Stores user details securely.
- **Environment-Based Configuration**: Customizable through environment variables.

### Upcoming Features
- **Google OAuth**: Integration with Google authentication.
- **Fingerprint & Passkey Login**: Advanced login options for enhanced security.

## Tech Stack
- **Node.js**
- **Express**
- **MongoDB** (via Mongoose)
- **JWT** for access and refresh tokens.
- **Nodemailer** for sending emails.
- **Express Rate Limit** for limiting excessive requests.
- **bcrypt** for secure password hashing.
- **cookie-parser** for managing cookies.
- **cors** for handling Cross-Origin Resource Sharing.
- **dotenv** for environment variable management.

## Installation & Setup
- 1. Clone the repository:
 ```bash
 git clone https://github.com/your-repo/user-auth-api.git
 ```

