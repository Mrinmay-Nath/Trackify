# 🐞 Trackify - Next-Gen Bug Tracking System

A **containerized, full-stack bug tracker** featuring real-time browser/email notifications, AI-powered tag generation, role-based access control, and modern DevOps workflows.

---

## 📂 Project Structure

```
bug-tracker-project/
├── backend/
│   ├── database/
│   │   └── schema.sql
│   ├── routes/
│   │   └── aiTags.js
│   ├── uploads/
│   │   └── attachments/
│   ├── .env
│   ├── package.json
│   └── server.js
├── frontend/
│   ├── assets/
│   │   ├── favicon/
│   │   └── logo.png
│   ├── index.html
│   ├── styles.css
│   └── script.js
├── docker-compose.yml
├── Dockerfile (backend)
└── Dockerfile (frontend)
```

---

## 🌟 Key Features

- 🔐 User Authentication (JWT-secured)
- 🧠 AI Tag Generation (Groq API)
- 📣 Real-time Notifications (Web API + Email)
- 📎 File Attachments
- 🔄 Auto Scheduled Reminders via `node-cron`
- 📊 Bug Dashboard with Filters/Stats
- 🛠️ Role-based Access: Admin, Developer, User
- 🚢 Fully Dockerized Deployment
- 🧪 Easily Testable & Scalable Structure
- 💅 Responsive UI with Modern Styling

---

## 🚀 Dockerized Setup (Production/Local)

### 1. Clone the Repository

```bash
git clone https://github.com/Mrinmay-Nath/Trackify.git
cd Trackify
```

### 2. Create `.env` in Root Directory

```env
PORT=3000
DB_HOST=mysql
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=bug_tracker
JWT_SECRET=supersecure_jwt_key
FRONTEND_URL=http://localhost:8080
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
SMTP_FROM=noreply@bugtracker.com
GROQ_API_KEY=your_groq_api_key
```

### 3. Build and Launch

```bash
docker-compose up --build
```

### Services

- 🔹 Frontend: [http://localhost:8080](http://localhost:8080)
- 🔹 Backend: [http://localhost:3000](http://localhost:3000)
- 🔹 MySQL: localhost:3307

---

## 🧪 Run Without Docker (Development Mode)

### Backend

```bash
cd backend
npm install
node server.js
```

### Frontend

Use VS Code Live Server or any HTTP server to launch `frontend/index.html`.

Ensure this in `.env`:

```env
DB_HOST=localhost
```

---

## 🔐 Default Admin Login

- Username: `admin`
- Password: `Admin@123`

*Change this immediately after login.*

---

## 🛠️ Usage Overview

### Authentication

- JWT-secured sessions
- LocalStorage for tokens
- Role-based dashboard rendering

### Bugs

- Add, Edit, Assign bugs
- AI-tag suggestions using Groq
- Upload screenshots/files
- Comment and update status

### Notifications

- 🔔 Web Notifications API (opt-in)
- ✉️ Email Alerts (SMTP)
- 🕒 Scheduled Reminders (via `node-cron`)

---

## 🧰 Tech Stack

### Backend

- Node.js, Express.js
- MySQL with native driver
- JWT Auth + bcrypt
- Multer, nodemailer, node-cron

### Frontend

- HTML5, CSS3, Vanilla JavaScript
- Responsive layout
- Fetch API for HTTP requests

---

## 📦 Deployment

- ⚙️ Docker + Compose ready
- 💡 Supports local + production
- 📤 SMTP Email Configurable
- 🎯 Flexible `.env`-driven environment

---

## 🤖 AI-Tagging via Groq

- Integrates Groq LLM API
- Converts bug descriptions into smart tags
- Returns context-aware suggestions for faster triage

---

## ⚠️ Troubleshooting

### CORS

```bash
Error: No 'Access-Control-Allow-Origin' header
```

✔️ Solution: Set `FRONTEND_URL` in `.env` to match your deployed URL

### SMTP Authentication (Gmail)

✔️ Use App Passwords for `SMTP_PASS` 📖 Guide: [Gmail App Passwords](https://support.google.com/mail/answer/185833)

### DB Authentication Mode

```sql
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'your_password';
FLUSH PRIVILEGES;
```

---

## 👥 Contribution Guidelines

1. Fork the repo
2. Create a new branch `feature/<name>`
3. Push and open a PR

---

## 📃 License

MIT License — use, modify, share freely

---

## 💡 Built with Passion

Crafted with ❤️ by **MRINMAY NATH**

