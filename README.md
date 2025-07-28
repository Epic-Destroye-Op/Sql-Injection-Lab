# SQL Injection Learning Lab

---

## 🔐 All Login Credentials

### Admin Account (Full Privileges)
**Username:** `admin`  
**Password:** `admin123`  
**Access:** Full database control including sensitive data

### Regular User Accounts
| Username    | Password     | Role       |
|-------------|--------------|------------|
| `john_doe`  | `password123`| Developer  |
| `alice`     | `qwerty`     | Designer   |
| `bob_smith` | `letmein`    | Manager    |
| `charlie`   | `123456`     | Intern     |

### SQL Injection Demo Accounts
```
Username: ' OR '1'='1'-- 
Password: [any value]

Username: ' UNION SELECT null,username,null,null,null,null FROM users--
Password: [any value]

Username: admin'--
Password: [any value]
```

---

## 🛠️ Installation & Usage

```
# Clone and run
git clone https://github.com/Epic-Destroye-Op/Sql-Injection-Lab.git
cd Sql-Injection-Lab
python3 sql-lab.py
```
Access at: `http://yourip:5000 or http://localhost:5000`

---

**DO NOT DEPLOY IN PRODUCTION!**

---
.
                                        **made by EpicDestroyerOp**
