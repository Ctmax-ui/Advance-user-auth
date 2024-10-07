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
1. Clone the repository:
 ```bash
 git clone https://github.com/your-repo/user-auth-api.git
 ```
2. Navigate to the project directory:
 ```bash
 cd user-auth-api
 ```
3. Install dependencies:
 ```bash
 npm install
 ```
4. Rename the .example.env to .env and fill all the value.
5. Start the server:
 ```bash
 npm start
 ```
The server should now be running on http://localhost:3000.



## API Endpoints

### 1. **User Registration**

- **POST**: `/api/v1/createuser`
- **Body**:

  ```json
  {
    "userName": "user",
    "userEmail": "user@gmail.com",
    "password": "user"
  }
- Description: Creates a new user with the given userName, userEmail, and password.

### 2. User Login
- **POST**: `/api/v1/login`
- **Body**:
 ```json
 {
   "userEmail": "user@gmail.com",
   "password": "user"
 }
 ```
- Description: Authenticates a user and returns JWT tokens.

### 3. User Logout
- **POST**: `/api/v1/logout`
- Description: Logs out the user by clearing their session cookies.

## 4. Update User Token
- **POST:** `/api/v1/userupdatetoken`  
- **Body:**
 ```json
 {
   "password": "user"
 }
 ```
- Description: Updates the user token and returns a new access token.

### 5. Update User Information
- **POST**: `/api/v1/updateuser`
- **Body:**
 ```json
 {
   "userName": "newUserName",
   "userEmail": "newUserEmail",
   "password": "newPassword"
 }
 ```
- Description: Updates the user's information.

### 6. Get User Information
- **POST**: `/api/v1/getuser`
- Description: Retrieves the current user's details.

### 7. Check User Access
- **POST**: `/api/v1/userhasaccess`
- Description: Checks if the user is currently authenticated.

### 8. Refresh Token
- **POST**: `/api/v1/refreshtoken`
- Description: Refreshes the access token if the user is still authenticated.

### 9. Request Reset Token
/ **POST**: `/api/v1/requestrtoken`
- **Body:**
 ```json
 {
   "userEmail": "user@gmail.com"
 }
 ```
- Description: Sends a password reset link to the provided email.

### 10. Reset Password
- **POST**: `/api/v1/resetpassword/:token`
- **Body:**
 ```json
 {
   "password": "newPassword"
 }
 ```
- Description: Resets the user's password using the provided reset token.

## Testing the API

You can use tools like **Postman** or **cURL** to test the API endpoints locally.

## Contributing

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Commit your changes (`git commit -am 'Add new feature'`).
4. Push to the branch (`git push origin feature-branch`).
5. Create a Pull Request.

## License

This project is licensed under the MIT License.

## Future Enhancements

- **Google OAuth Integration**
- **Fingerprint & Passkey Login**
- **Enhanced Rate Limiting and Security**

Feel free to contribute or raise issues if you encounter any bugs!
