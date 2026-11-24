import os
import uuid
import boto3
import pymysql
from botocore.config import Config
from botocore.exceptions import ClientError
from dotenv import load_dotenv
from flask import Flask, request, jsonify, session, render_template
from flask_cors import CORS
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key")
# Cho phép nhận file tối đa 600MB ở Cách 1 (Proxy Upload)
app.config["MAX_CONTENT_LENGTH"] = 600 * 1024 * 1024
CORS(app, supports_credentials=True)

AWS_REGION = os.getenv("AWS_REGION", "ap-southeast-1")
S3_BUCKET = os.getenv("S3_BUCKET_NAME")

# Bắt buộc dùng signature s3v4 để Pre-signed URL hoạt động ổn định trên mọi Region
s3_client = boto3.client(
    "s3",
    region_name=AWS_REGION,
    config=Config(signature_version="s3v4")
)

def get_db_connection():
    """Mở kết nối mới tới RDS khi cần ghi/đọc để tránh lỗi timeout khi upload file lớn"""
    return pymysql.connect(
        host=os.getenv("RDS_HOST"),
        user=os.getenv("RDS_USER"),
        password=os.getenv("RDS_PASSWORD"),
        database=os.getenv("RDS_DB"),
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor
    )

def save_document_to_rds(file_name, s3_key, file_size_mb, method, is_public, owner_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
                INSERT INTO documents (file_name, s3_key, file_size_mb, upload_method, is_public, owner_id)
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            cursor.execute(sql, (file_name, s3_key, round(file_size_mb, 2), method, int(is_public), owner_id))
        conn.commit()
    finally:
        conn.close()

# ==================== 1. GIAO DIỆN & ĐĂNG NHẬP ====================

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, username FROM users WHERE username=%s AND password=%s", (username, password))
            user = cursor.fetchone()
            if user:
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                return jsonify({"message": "Đăng nhập thành công", "user": user})
            return jsonify({"error": "Sai tài khoản hoặc mật khẩu"}), 401
    finally:
        conn.close()

@app.route("/api/me", methods=["GET"])
def current_user():
    # Mặc định trả về user id=1 (sv1) nếu chưa login để dễ chạy test k6
    user_id = session.get("user_id", 1)
    username = session.get("username", "sv1")
    return jsonify({"user_id": user_id, "username": username})

# ==================== 2. QUẢN LÝ FILE, PHÂN QUYỀN & LINK TẢI CÓ THỜI HẠN ====================

@app.route("/api/files", methods=["GET"])
def list_files():
    user_id = session.get("user_id", 1)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
                SELECT d.*, u.username AS owner_name
                FROM documents d
                JOIN users u ON d.owner_id = u.id
                WHERE d.owner_id = %s OR d.is_public = 1
                ORDER BY d.created_at DESC
            """
            cursor.execute(sql, (user_id,))
            files = cursor.fetchall()
            return jsonify(files)
    finally:
        conn.close()

@app.route("/api/files/<int:file_id>/toggle-share", methods=["POST"])
def toggle_share(file_id):
    user_id = session.get("user_id", 1)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT owner_id, is_public FROM documents WHERE id=%s", (file_id,))
            doc = cursor.fetchone()
            if not doc:
                return jsonify({"error": "Không tìm thấy tệp"}), 404
            if doc["owner_id"] != user_id:
                return jsonify({"error": "Bạn không có quyền đổi trạng thái tệp này"}), 403

            new_status = 0 if doc["is_public"] == 1 else 1
            cursor.execute("UPDATE documents SET is_public=%s WHERE id=%s", (new_status, file_id))
        conn.commit()
        return jsonify({"message": "Đã cập nhật quyền chia sẻ", "is_public": new_status})
    finally:
        conn.close()

@app.route("/api/files/<int:file_id>/download", methods=["GET"])
def get_download_link(file_id):
    user_id = session.get("user_id", 1)
    # Thời hạn link tải (mặc định 60 giây để dễ demo hết hạn)
    expires_in = int(request.args.get("expires", 60))

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM documents WHERE id=%s", (file_id,))
            doc = cursor.fetchone()
            if not doc:
                return jsonify({"error": "Không tìm thấy tệp"}), 404
            if doc["owner_id"] != user_id and doc["is_public"] == 0:
                return jsonify({"error": "Tệp riêng tư, bạn không có quyền tải"}), 403

            url = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": S3_BUCKET,
                    "Key": doc["s3_key"],
                    "ResponseContentDisposition": f'attachment; filename="{doc["file_name"]}"'
                },
                ExpiresIn=expires_in
            )
            return jsonify({"download_url": url, "expires_in": expires_in})
    finally:
        conn.close()

# ==================== 3. CÁCH 1: PROXY UPLOAD (QUA EC2) ====================

@app.route("/api/upload/proxy", methods=["POST"])
def upload_proxy():
    if "file" not in request.files:
        return jsonify({"error": "Thiếu tệp tải lên"}), 400

    file = request.files["file"]
    is_public = request.form.get("is_public", 0)
    user_id = session.get("user_id", 1)

    safe_name = secure_filename(file.filename) or "uploaded_file.bin"
    s3_key = f"proxy/{uuid.uuid4()}_{safe_name}"

    # Tính dung lượng tệp (MB)
    file.seek(0, os.SEEK_END)
    file_size_mb = file.tell() / (1024 * 1024)
    file.seek(0)

    # EC2 tự đẩy tệp lên S3
    s3_client.upload_fileobj(
        file,
        S3_BUCKET,
        s3_key,
        ExtraArgs={"ContentType": file.content_type or "application/octet-stream"}
    )

    # EC2 ghi thông tin vào RDS
    save_document_to_rds(safe_name, s3_key, file_size_mb, "proxy", is_public, user_id)
    return jsonify({"message": "Tải lên qua Proxy thành công", "s3_key": s3_key})

# ==================== 4. CÁCH 2: PRE-SIGNED PUT URL ====================

@app.route("/api/upload/presigned", methods=["POST"])
def get_presigned_upload():
    data = request.json
    safe_name = secure_filename(data.get("file_name", "file.bin"))
    content_type = data.get("content_type", "application/octet-stream")
    s3_key = f"presigned/{uuid.uuid4()}_{safe_name}"

    # Cấp link tạm hiệu lực 30 phút (1800s) để đủ tải file 500MB mạng chậm
    upload_url = s3_client.generate_presigned_url(
        "put_object",
        Params={"Bucket": S3_BUCKET, "Key": s3_key, "ContentType": content_type},
        ExpiresIn=1800
    )
    return jsonify({"upload_url": upload_url, "s3_key": s3_key})

@app.route("/api/upload/presigned/confirm", methods=["POST"])
def confirm_presigned_upload():
    data = request.json
    s3_key = data.get("s3_key")
    file_name = data.get("file_name")
    file_size_mb = float(data.get("file_size_mb", 0))
    is_public = data.get("is_public", 0)
    user_id = session.get("user_id", 1)

    # Kiểm tra chắc chắn tệp đã nằm trên S3 trước khi ghi vào RDS
    try:
        s3_client.head_object(Bucket=S3_BUCKET, Key=s3_key)
    except ClientError:
        return jsonify({"error": "Tệp chưa tồn tại trên S3"}), 400

    save_document_to_rds(file_name, s3_key, file_size_mb, "presigned", is_public, user_id)
    return jsonify({"message": "Xác nhận lưu tệp Pre-signed thành công"})

# ==================== 5. CÁCH 3: MULTIPART UPLOAD ====================

@app.route("/api/upload/multipart/start", methods=["POST"])
def start_multipart():
    data = request.json
    safe_name = secure_filename(data.get("file_name", "file.bin"))
    total_parts = int(data.get("total_parts", 1))
    content_type = data.get("content_type", "application/octet-stream")
    s3_key = f"multipart/{uuid.uuid4()}_{safe_name}"

    # Mở phiên Multipart trên S3
    mp = s3_client.create_multipart_upload(
        Bucket=S3_BUCKET,
        Key=s3_key,
        ContentType=content_type
    )
    upload_id = mp["UploadId"]

    # Tạo sẵn danh sách Pre-signed URL cho từng mảnh (từ 1 đến total_parts)
    part_urls = []
    for part_num in range(1, total_parts + 1):
        url = s3_client.generate_presigned_url(
            "upload_part",
            Params={
                "Bucket": S3_BUCKET,
                "Key": s3_key,
                "UploadId": upload_id,
                "PartNumber": part_num
            },
            ExpiresIn=3600
        )
        part_urls.append({"part_number": part_num, "url": url})

    return jsonify({
        "upload_id": upload_id,
        "s3_key": s3_key,
        "urls": part_urls
    })

@app.route("/api/upload/multipart/complete", methods=["POST"])
def complete_multipart():
    data = request.json
    s3_key = data.get("s3_key")
    upload_id = data.get("upload_id")
    parts = data.get("parts", [])  # [{"PartNumber": 1, "ETag": "..."}, ...]
    file_name = data.get("file_name")
    file_size_mb = float(data.get("file_size_mb", 0))
    is_public = data.get("is_public", 0)
    user_id = session.get("user_id", 1)

    # Sắp xếp đúng thứ tự PartNumber theo quy định của AWS S3
    sorted_parts = sorted(
        [{"PartNumber": int(p["PartNumber"]), "ETag": p["ETag"]} for p in parts],
        key=lambda x: x["PartNumber"]
    )

    # Ra lệnh cho S3 ghép các mảnh thành tệp hoàn chỉnh
    s3_client.complete_multipart_upload(
        Bucket=S3_BUCKET,
        Key=s3_key,
        UploadId=upload_id,
        MultipartUpload={"Parts": sorted_parts}
    )

    # Ghi thông tin tệp vào RDS
    save_document_to_rds(file_name, s3_key, file_size_mb, "multipart", is_public, user_id)
    return jsonify({"message": "Ghép tệp Multipart thành công"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
