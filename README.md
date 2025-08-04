# 🔐 MERN Stack Multi-Level User Management System (with Paid Access)

A secure, scalable, and role-based access control system built using the MERN stack. This system supports **Main Admin**, **Sub-Admin**, and **User** levels with code-based access, auto-login, and package expiry.

---

## 🧱 Technologies Used

| 🔧 Tool              | 🔎 Description          |
| -------------------- | ----------------------- |
| 🧠 **MongoDB**       | Data storage            |
| 🚀 **Express.js**    | Backend logic           |
| ⚛️ **React.js**      | Frontend UI             |
| 🌐 **Node.js**       | Runtime environment     |
| 🛡️ **JWT**           | Access & Refresh Tokens |
| 🧂 **bcrypt**        | Password hashing        |
| 🍪 **cookie-parser** | Refresh token cookies   |
| 💨 **Tailwind CSS**  | Responsive UI           |
| 🍃 **Mongoose**      | MongoDB ORM             |
| 🔐 **dotenv**        | Env variable management |

---

## 🧑‍🤝‍🧑 User Roles

### 👤 **User**

- Code দিয়ে Sub-admin কে দেয়
- Sub-admin তাকে অ্যাড করলে auto-login হয়
- একসাথে একটাই ডিভাইসে active থাকতে পারে
- কোড দিয়েই এক্সেস পায়
- Sub-admin মুছে ফেললে logout হয়ে যায়

### 👥 **Sub-Admin**

- নিজের ইউজার ম্যানেজ করতে পারে
- নাম, কোড, প্যাকেজ সহ ইউজার অ্যাড করে
- মেয়াদ (24h, 3d, 7d) নির্ধারণ করে
- এক ডিভাইসে একবারে লগইন থাকতে পারে
- মেয়াদ শেষ হলে auto logout হয়

### 👑 **Main Admin**

- Sub-admin তৈরি ও মুছে ফেলতে পারে
- Sub-admin এর পেমেন্ট manually active করে
- সকল Sub-admin ও তাদের ইউজার দেখতে পারে
- Crash Value update করতে পারে
- System-wide logs ও analytics দেখতে পারে

---

## 🔄 Workflow

### ▶️ **User**

1. কোড জেনারেট করে
2. Sub-admin কে দেয়
3. Sub-admin অ্যাড করলে auto-login হয়
4. মেয়াদ শেষ হলে logout হয়ে যায়

### ▶️ **Sub-Admin**

1. Main Admin থেকে username/password নিয়ে login
2. ইউজার অ্যাড করে (code + name + package)
3. Expired users দেখতে পায়
4. পেমেন্ট হলে Main-admin access দেয়

### ▶️ **Main Admin**

1. Sub-admin তৈরি করে
2. Sub-admin ও তাদের users দেখে
3. Sub-admin expire বা delete করতে পারে
4. Logs এবং Crash value manage করে

---

## 💎 Key Features

| Feature                | Description                            |
| ---------------------- | -------------------------------------- |
| 🔐 **JWT Auth**        | Access + Refresh token authentication  |
| 👮‍♂️ **Role Middleware** | User/Sub-Admin/Main-Admin control      |
| 🔒 **Device Locking**  | One-device-at-a-time session           |
| 🧾 **Activity Logs**   | সমস্ত কাজের record                     |
| ⏳ **Package Expiry**  | 24h, 3d, 7d based expiry & auto logout |
| 📊 **Admin Dashboard** | Total users, active/inactive stats     |
| 🔍 **User Search**     | Sub-admin can search by name/code      |
| 📦 **Add User Modal**  | Name + Code + Package add interface    |
| 🔁 **Auto Logout**     | Expiry-based logout handled by backend |

---

## 📁 Folder Structure

backend/
├── controllers/
│ ├── authController.js ← Login, Logout, Refresh
│ ├── userController.js ← User management ✅
│ ├── subAdminController.js ← (to be implemented)
│ ├── mainAdminController.js ← (to be implemented)
│ └── logsController.js ← (to be implemented)
├── middleware/
│ ├── auth.js ← JWT verification
│ ├── role.js ← Role-based access
│ └── rateLimiter.js ← Rate limiting
├── models/
│ ├── User.js ← User model ✅
│ ├── SubAdmin.js ← SubAdmin model ✅
│ ├── MainAdmin.js ← MainAdmin model ✅
│ ├── ActivityLog.js ← Logs model ✅
│ └── index.js ← Model export
├── routes/
│ ├── authRoutes.js ← (to be implemented)
│ ├── userRoutes.js ← (to be implemented)
│ ├── adminRoutes.js ← (to be implemented)
├── utils/
│ ├── generateTokens.js ← Access + Refresh
│ └── dateUtil.js ← Expiry calculations
├── .env ← Env variables ✅
├── package.json ← Dependencies ✅
└── server.js ← Entry point ✅

---

## 🔐 Security Features

| ✅ Status | 🔒 Feature             | 🛠️ Tools Used            |
| --------- | ---------------------- | ------------------------ |
| ✅        | Password Hashing       | bcrypt                   |
| ✅        | JWT Auth               | Access + Refresh         |
| ✅        | Role Middleware        | auth.js, role.js         |
| ✅        | Rate Limiting          | express-rate-limit       |
| ✅        | HTTP Headers Secure    | helmet                   |
| ✅        | MongoDB Injection Safe | express-mongo-sanitize   |
| ✅        | HTTPS Enforced         | Production server setup  |
| ✅        | Cookie-based Refresh   | httpOnly, Secure cookies |
| ✅        | Device Locking         | deviceId-based session   |

---

## ⚙️ Setup Instructions

### 1️⃣ Install dependencies

```bash
cd backend
npm install


✍️ Author
Made with ❤️ by Ahnaf Tazwar Akash PK
```
