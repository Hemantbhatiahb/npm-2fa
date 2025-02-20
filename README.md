# 2FAuth - Secure Authentication with JWT & 2FA  

![npm](https://img.shields.io/npm/v/2fauth) ![license](https://img.shields.io/npm/l/2fauth) ![downloads](https://img.shields.io/npm/dt/2fauth)  

🚀 **2FAuth** is a plug-and-play authentication system for Node.js/Express apps, featuring:  
✅ **User Registration & Login**  
✅ **JWT Authentication**  
✅ **Email Verification**  
✅ **Two-Factor Authentication (2FA)**  
✅ **Password Reset**  

---

## 🏗️ Installation  

Install 2FAuth via NPM:  

```sh
npm install 2fauth
```

## 🚀 Usage
Import and initialize authentication in your Express app:

```js
const express = require("express");
const { initAuth } = require("2fauth");

const app = express();

app.use(
  initAuth({
    mongoUrl: "mongodb+srv://your-mongo-db",
    jwtSecretKey: "your-secret-key",
    emailConfig: {
      fromEmail: "noreply@example.com",
      transportOptions: {
        service: "gmail",
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASSWORD,
        },
      },
    },
  })
);

app.listen(5000, () => console.log("Auth system running!"));
```

## 📡 API Endpoints  

| Method  | Endpoint                | Description                     |
|---------|-------------------------|---------------------------------|
| **POST** | `/auth/register`        | Register a new user            |
| **GET**  | `/auth/verify-email`    | Verify user email              |
| **POST** | `/auth/login`           | User Login                     |
| **POST** | `/auth/enable-2fa`      | Enable 2FA (Generates QR code) |
| **POST** | `/auth/verify-2fa`      | Verify OTP for 2FA             |
| **POST** | `/auth/logout`          | Logout the user                |
| **POST** | `/auth/forgot-password` | Initiate password reset        |
| **POST** | `/auth/reset-password`  | Reset password                 |

## 🚀 Usage Examples

### **🔹 Register a New User**
```bash
curl -X POST http://localhost:8000/auth/register \
     -H "Content-Type: application/json" \
     -d '{
           "name": "John Doe",
           "email": "johndoe@example.com",
           "password": "securepassword"
         }'
```
### 📌 Response (Success)
```json
{
  "success": true,
  "message": "User registered successfully. Please verify your email"
}
```

### **🔹 Login a User**
```bash
curl -X POST http://localhost:8000/auth/login \
     -H "Content-Type: application/json" \
     -d '{
           "email": "johndoe@example.com",
           "password": "securepassword"
         }'
```

### 📌 Response (Success)
```json
{
  "success": true,
  "message": "Login Successful"
}
```

## 🤝 Contributing
Contributions are welcome! If you find a bug or want to add a feature, feel free to open an issue or submit a PR.

## ⚖️ License
MIT License - Free to use and modify!


