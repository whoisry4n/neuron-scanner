from flask import Flask, render_template, request
import os
import time
import sqlite3
import math
from datetime import datetime
from werkzeug.utils import secure_filename
from urllib.parse import urlparse

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32MB max file size

DB_FILE = 'scans2.db'

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            type TEXT NOT NULL,
            target TEXT NOT NULL,
            result TEXT NOT NULL,
            positives INTEGER,
            total INTEGER
        )
    ''')
    conn.commit()
    conn.close()

def insert_scan(scan_type, target, result, positives=None, total=None):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute('''
        INSERT INTO scans (timestamp, type, target, result, positives, total)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (timestamp, scan_type, target, result, positives, total))
    conn.commit()
    conn.close()

def delete_file(filepath):
    try:
        if os.path.exists(filepath):
            os.remove(filepath)
    except OSError:
        pass

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        if 'url' in request.form and request.form['url'].strip():
            url = request.form['url'].strip()
            scan_result = self_scan_url(url)
            positives, total = extract_positives_total(scan_result)
            insert_scan('URL', url, scan_result, positives, total)
            result = scan_result

        elif 'file' in request.files:
            file = request.files['file']
            if file and file.filename:
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                try:
                    scan_result = self_scan_file(filepath)
                    positives, total = extract_positives_total(scan_result)
                    insert_scan('File', filename, scan_result, positives, total)
                    result = scan_result
                finally:
                    delete_file(filepath)
            else:
                result = 'Vui lòng chọn một file hợp lệ để kiểm tra.'
    
    return render_template('index2.html', result=result, now=datetime.now().strftime('%H:%M:%S'))

def extract_positives_total(result_text):
    if 'an toàn' in result_text.lower():
        return 0, 5
    try:
        # Đếm số lượng rủi ro dựa trên ký tự ngăn cách "|"
        positives = result_text.count('|') + 1 if 'rủi ro!' in result_text else 0
        total = 5
        return positives, total
    except:
        return None, None

def self_scan_url(url):
    risks = []
    try:
        parsed = urlparse(url)
        # Nếu người dùng nhập link không có http/https, urlparse sẽ không lấy được hostname
        if not parsed.scheme:
            parsed = urlparse('http://' + url)
            
        hostname = parsed.hostname.lower() if parsed.hostname else ""
        full_url = url.lower()

        # 1. Kiểm tra độ dài
        if len(url) > 100:
            risks.append("URL có độ dài bất thường (>100 ký tự)")

        # 2. Kiểm tra Subdomain (Dấu hiệu giả mạo sâu)
        subdomains = hostname.split('.')
        if len(subdomains) > 3:
            risks.append(f"Số lượng subdomain quá nhiều ({len(subdomains)})")

        # 3. Tên miền cấp cao (TLD) rủi ro (Các link PhishTank thường dùng đuôi rẻ tiền)
        bad_tlds = ['.xyz', '.top', '.site', '.online', '.zip', '.icu', '.cfd', '.tk', '.ml', '.ga']
        if any(hostname.endswith(tld) for tld in bad_tlds):
            risks.append("Sử dụng TLD rủi ro cao (thường dùng cho phishing)")

        # 4. Kiểm tra từ khóa nhạy cảm
        sensitive_keywords = [
            "login", "verify", "secure", "account", "update", "banking", 
            "confirm", "signin", "wp-admin", "winner", "reward", "free"
        ]
        found_keys = [key for key in sensitive_keywords if key in full_url]
        if found_keys:
            risks.append(f"Chứa từ khóa nhạy cảm: {', '.join(found_keys)}")

        # 5. Dấu hiệu giả mạo thương hiệu (Brand Spoofing)
        # Ví dụ: mbbank.verify-secure.com -> mbbank nằm trong subdomain chứ không phải domain chính
        brands = ["google", "facebook", "microsoft", "apple", "paypal", "binance", "vcb", "mbbank", "vietcombank"]
        for brand in brands:
            if brand in full_url:
                # Nếu brand xuất hiện nhưng không phải là domain chính (phần sát TLD)
                domain_parts = hostname.split('.')
                main_domain = domain_parts[-2] if len(domain_parts) >= 2 else ""
                if brand not in main_domain:
                    risks.append(f"Dấu hiệu giả mạo thương hiệu: {brand}")

        # 6. Ký tự nguy hiểm
        if any(c in full_url for c in ['%', '..', '<', '>', '$', '{', '}']):
            risks.append("Chứa ký tự đặc biệt nguy hiểm")

        # 7. Danh sách đen trực tiếp
        blacklist = ["malware", "phish", "scam", "virus"]
        if any(bad in hostname for bad in blacklist):
            risks.append("Domain nằm trong danh sách đen")

    except Exception as e:
        return f"Lỗi phân tích URL: {str(e)}"
    
    if risks:
        return f'URL có rủi ro! Lý do: {" | ".join(risks)}'
    return 'URL an toàn theo các bước kiểm tra.'

def self_scan_file(filepath):
    risks = []
    filename = os.path.basename(filepath)
    ext = os.path.splitext(filename)[1].lower()
    size = os.path.getsize(filepath) / (1024*1024)
    
    dangerous_ext = ['.exe', '.bat', '.scr', '.pif', '.com', '.js', '.vbs', '.ps1']
    is_executable = ext in dangerous_ext
    
    if is_executable:
        risks.append(f"File thực thi nguy hiểm {ext}")
    
    if size > 50:
        risks.append("File quá lớn (>50MB)")
    elif size == 0:
        risks.append("File rỗng")
    
    with open(filepath, 'rb') as f:
        data = f.read()
    
    if data:
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        entropy = -sum((f / len(data)) * math.log2(f / len(data)) for f in freq if f > 0)
        
        if is_executable and entropy > 7.5:
            risks.append(f"Entropy cao ({entropy:.2f}) - nghi ngờ packed")
        elif not is_executable and entropy > 7.999:
            risks.append(f"Entropy cực cao bất thường ({entropy:.2f})")
            
        content_sample = data[:1024*1024]
        
        # Obfuscation cho chính code này để không tự nhận diện nhầm
        if is_executable:
            suspicious = [
                b'cm' + b'd.ex' + b'e', 
                b'power' + b'shell', 
                b'ht' + b'tp://', 
                b'ht' + b'tps://', 
                b'M' + b'Z'
            ]
        else:
            suspicious = [
                b'c' + b'md.' + b'ex' + b'e', 
                b'powe' + b'rshe' + b'll'
            ]
            
        found = [s.decode(errors='ignore') for s in suspicious if s in content_sample]
        if found:
            risks.append(f"Chứa lệnh thực thi: {', '.join(found)}")

    if risks:
        return f'File có rủi ro! Lý do: {" | ".join(risks)}'
    return 'File an toàn theo các bước kiểm tra.'

@app.route('/history')
def history():
    scans = []
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT timestamp, type, target, result, positives, total FROM scans ORDER BY id DESC LIMIT 100')
        scans = cursor.fetchall()
        conn.close()
    except sqlite3.Error as e:
        print(f"Lỗi database: {e}")
    return render_template('history2.html', scans=scans)

@app.route('/documentation')
def documentation():
    # Render trang tài liệu
    return render_template('documentation.html')

if __name__ == '__main__':
    init_db()
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(host='0.0.0.0', port=5000, debug=True)