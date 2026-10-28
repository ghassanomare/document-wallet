import http.server
import socketserver
import json
import os
import base64
import hashlib
import secrets
from urllib.parse import urlparse, parse_qs

PORT = int(os.environ.get("PORT", 8083))
DOCUMENTS_FILE = "documents.json"
USERS_FILE = "users.json"
UPLOAD_DIR = "uploads"

# تخزين مؤقت لأكواد الـ 2FA النشطة (الهاتف -> الكود)
pending_2fa = {}

# التأكد من وجود مجلد الرفع وملفات البيانات
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

if not os.path.exists(DOCUMENTS_FILE):
    with open(DOCUMENTS_FILE, "w", encoding="utf-8") as f:
        json.dump({}, f)

if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump({}, f)

def hash_password(password, salt=None):
    """توليد هاش آمن لتشفير كلمة المرور مع Salt"""
    if not salt:
        salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000).hex()
    return f"{salt}${pwd_hash}"

def verify_password(stored_password, provided_password):
    """التحقق من صحة كلمة المرور المدخلة مقارنة بالمخزنة (مع دعم التوافقية مع القديم أو المشفر)"""
    if not stored_password:
        return False
    # إذا كانت مخزنة بالطريقة القديمة (نص صريح)
    if '$' not in stored_password:
        return stored_password == provided_password
    try:
        salt, pwd_hash = stored_password.split('$')
        return stored_password == hash_password(provided_password, salt)
    except:
        return False

class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        
        try:
            data = json.loads(body.decode('utf-8'))
        except:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Invalid JSON")
            return

        # 1. تسجيل حساب جديد
        if self.path == '/api/register':
            phone = data.get('phone')
            password = data.get('password')
            
            with open(USERS_FILE, 'r', encoding='utf-8') as f:
                users = json.load(f)
                
            if phone in users:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "المستخدم مسجل مسبقاً"}, ensure_ascii=False).encode('utf-8'))
                return
                
            secure_pwd = hash_password(password)
            users[phone] = {"password": secure_pwd, "name": "مستخدم جديد", "avatar": ""}
            with open(USERS_FILE, 'w', encoding='utf-8') as f:
                json.dump(users, f, ensure_ascii=False, indent=4)
                
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"success": True}, ensure_ascii=False).encode('utf-8'))

        # 2. خطوة تسجيل الدخول الأولى (التحقق من الهاتف والباسورد وإرسال كود 2FA)
        elif self.path == '/api/login':
            phone = data.get('phone')
            password = data.get('password')
            
            with open(USERS_FILE, 'r', encoding='utf-8') as f:
                users = json.load(f)
                
            if phone not in users or not verify_password(users[phone].get("password"), password):
                self.send_response(401)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "رقم الهاتف أو كلمة المرور غير صحيحة"}, ensure_ascii=False).encode('utf-8'))
                return
                
            # توليد كود تحقق عشوائي من 6 أرقام للـ 2FA
            otp_code = "".join([str(secrets.randbelow(10)) for _ in range(6)])
            pending_2fa[phone] = otp_code
            
            # طباعة الكود في الـ Terminal كبديل لإرسال رسالة SMS حقيقية
            print(f"\n========================================")
            print(f" [2FA CODE] Verification code for {phone}: {otp_code}")
            print(f"========================================\n")
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"requires_2fa": True, "phone": phone}, ensure_ascii=False).encode('utf-8'))

        # 3. خطوة التحقق من الـ 2FA وتأكيد الدخول
        elif self.path == '/api/verify-2fa':
            phone = data.get('phone')
            code = data.get('code')
            
            if phone in pending_2fa and pending_2fa[phone] == code:
                del pending_2fa[phone]  # حذف الكود بعد استخدامه بنجاح
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"success": True, "phone": phone}, ensure_ascii=False).encode('utf-8'))
            else:
                self.send_response(401)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "رمز التحقق (2FA) غير صحيح أو انتهت صلاحيته"}, ensure_ascii=False).encode('utf-8'))

        # 4. تحديث الملف الشخصي
        elif self.path == '/api/update-profile':
            phone = data.get('phone')
            name = data.get('name')
            password = data.get('password')
            avatar = data.get('avatar')

            with open(USERS_FILE, 'r', encoding='utf-8') as f:
                users = json.load(f)

            if phone in users:
                if name is not None:
                    users[phone]["name"] = name
                if password:
                    users[phone]["password"] = hash_password(password)
                if avatar is not None:
                    users[phone]["avatar"] = avatar

                with open(USERS_FILE, 'w', encoding='utf-8') as f:
                    json.dump(users, f, ensure_ascii=False, indent=4)

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"success": True, "user": {"name": users[phone]["name"], "avatar": users[phone]["avatar"]}}, ensure_ascii=False).encode('utf-8'))
            else:
                self.send_response(404)
                self.end_headers()

        # 5. رفع الصور للمستندات
        elif self.path == '/api/upload':
            phone = data.get('phone')
            doc_key = data.get('docKey')
            file_data = data.get('fileData')
            file_name = data.get('fileName')

            if not phone or not doc_key or not file_data:
                self.send_response(400)
                self.end_headers()
                return

            header, encoded = file_data.split(",", 1)
            file_bytes = base64.b64decode(encoded)
            file_path = os.path.join(UPLOAD_DIR, f"{phone}_{doc_key}_{file_name}")

            with open(file_path, "wb") as f:
                f.write(file_bytes)

            with open(DOCUMENTS_FILE, "r", encoding="utf-8") as f:
                all_docs = json.load(f)

            if phone not in all_docs:
                all_docs[phone] = {}

            all_docs[phone][doc_key] = f"/{UPLOAD_DIR}/{phone}_{doc_key}_{file_name}"

            with open(DOCUMENTS_FILE, "w", encoding="utf-8") as f:
                json.dump(all_docs, f, ensure_ascii=False, indent=4)

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Success")

        # 6. حذف صورة المستند
        elif self.path == '/api/delete':
            phone = data.get('phone')
            doc_key = data.get('docKey')
            
            with open(DOCUMENTS_FILE, "r", encoding="utf-8") as f:
                all_docs = json.load(f)

            if phone in all_docs and doc_key in all_docs[phone]:
                file_path_relative = all_docs[phone][doc_key]
                clean_path = file_path_relative.lstrip('/')
                
                if os.path.exists(clean_path):
                    try:
                        os.remove(clean_path)
                    except Exception as e:
                        print(f"Error deleting file: {e}")

                del all_docs[phone][doc_key]
                
                with open(DOCUMENTS_FILE, "w", encoding="utf-8") as f:
                    json.dump(all_docs, f, ensure_ascii=False, indent=4)

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Deleted")
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query_params = parse_qs(parsed_url.query)

        if path == '/api/documents':
            phone = query_params.get('phone', [None])[0]
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            with open(DOCUMENTS_FILE, "r", encoding="utf-8") as f:
                all_docs = json.load(f)
                
            user_docs = all_docs.get(phone, {}) if phone else {}
            self.wfile.write(json.dumps(user_docs, ensure_ascii=False).encode('utf-8'))

        elif path == '/api/user-info':
            phone = query_params.get('phone', [None])[0]
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                users = json.load(f)
                
            user = users.get(phone, {})
            user_data = {"name": user.get("name", "مستخدم"), "avatar": user.get("avatar", "")}
            self.wfile.write(json.dumps(user_data, ensure_ascii=False).encode('utf-8'))
        else:
            super().do_GET()

with socketserver.TCPServer(("", PORT), CustomHandler) as httpd:
    print(f"Server running at http://localhost:{PORT}")
    httpd.serve_forever()