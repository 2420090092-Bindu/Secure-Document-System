from flask import Flask, request
import os
import hashlib
import sqlite3
import base64
from datetime import datetime
import shutil
import difflib

from docx import Document

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed


app = Flask(__name__)


# =========================================================
# PATHS
# =========================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ORIGINAL_FOLDER = os.path.join(BASE_DIR, "originals")
DATABASE = os.path.join(BASE_DIR, "database", "documents.db")

PRIVATE_KEY = os.path.join(BASE_DIR, "keys", "private_key.pem")
PUBLIC_KEY = os.path.join(BASE_DIR, "keys", "public_key.pem")

FRONTEND_FILE = os.path.join(BASE_DIR, "frontend", "index.html")


# =========================================================
# CREATE REQUIRED FOLDERS
# =========================================================

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ORIGINAL_FOLDER, exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, "database"), exist_ok=True)


# =========================================================
# DATABASE
# =========================================================

def create_database():

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT NOT NULL,
            sha512_hash TEXT NOT NULL,
            upload_date TEXT NOT NULL,
            signature TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS verification_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER NOT NULL,
            file_name TEXT NOT NULL,
            verification_result TEXT NOT NULL,
            verification_date TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


create_database()


# =========================================================
# SHA-512 HASH
# =========================================================

def generate_sha512(file_path):

    sha512 = hashlib.sha512()

    with open(file_path, "rb") as file:

        while True:

            data = file.read(4096)

            if not data:
                break

            sha512.update(data)

    return sha512.hexdigest()


# =========================================================
# CREATE DIGITAL SIGNATURE
# =========================================================

def create_digital_signature(document_hash):

    with open(PRIVATE_KEY, "rb") as private_file:

        private_key = serialization.load_pem_private_key(
            private_file.read(),
            password=None
        )

    hash_bytes = bytes.fromhex(document_hash)

    signature = private_key.sign(
        hash_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA512()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        Prehashed(hashes.SHA512())
    )

    return base64.b64encode(signature).decode("utf-8")


# =========================================================
# VERIFY DIGITAL SIGNATURE
# =========================================================

def verify_digital_signature(document_hash, signature_base64):

    try:

        with open(PUBLIC_KEY, "rb") as public_file:

            public_key = serialization.load_pem_public_key(
                public_file.read()
            )

        signature = base64.b64decode(signature_base64)

        hash_bytes = bytes.fromhex(document_hash)

        public_key.verify(
            signature,
            hash_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            Prehashed(hashes.SHA512())
        )

        return True

    except Exception:

        return False


# =========================================================
# SAVE VERIFICATION HISTORY
# =========================================================

def save_verification_history(document_id, file_name, result):

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO verification_history
        (
            document_id,
            file_name,
            verification_result,
            verification_date
        )
        VALUES (?, ?, ?, ?)
    """, (
        document_id,
        file_name,
        result,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    connection.commit()
    connection.close()


# =========================================================
# READ DOCX TEXT
# =========================================================

def read_docx_text(file_path):

    document = Document(file_path)

    text = []

    for paragraph in document.paragraphs:

        if paragraph.text.strip():

            text.append(paragraph.text.strip())

    for table in document.tables:

        for row in table.rows:

            row_text = []

            for cell in row.cells:

                row_text.append(cell.text.strip())

            text.append(" | ".join(row_text))

    return text


# =========================================================
# COMPARE WORD DOCUMENTS
# =========================================================

def compare_word_documents(original_file, modified_file):

    original_text = read_docx_text(original_file)

    modified_text = read_docx_text(modified_file)

    matcher = difflib.SequenceMatcher(
        None,
        original_text,
        modified_text
    )

    changes = []

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():

        if tag == "replace":

            changes.append((
                "replace",
                original_text[i1:i2],
                modified_text[j1:j2]
            ))

        elif tag == "delete":

            changes.append((
                "delete",
                original_text[i1:i2],
                []
            ))

        elif tag == "insert":

            changes.append((
                "insert",
                [],
                modified_text[j1:j2]
            ))

    return changes


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():

    try:

        with open(
            FRONTEND_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            return file.read()

    except FileNotFoundError:

        return """
        <h1> Frontend file not found</h1>

        <p>
        Please make sure frontend/index.html exists.
        </p>
        """


# =========================================================
# REGISTER DOCUMENT
# =========================================================

@app.route("/upload", methods=["POST"])
def upload():

    if "file" not in request.files:

        return "No file uploaded."

    file = request.files["file"]

    if file.filename == "":

        return "No file selected."

    file_path = os.path.join(
        UPLOAD_FOLDER,
        file.filename
    )

    file.save(file_path)

    # Generate SHA-512
    document_hash = generate_sha512(file_path)

    # Create RSA digital signature
    signature = create_digital_signature(
        document_hash
    )

    upload_date = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # Save document in database
    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO documents
        (
            file_name,
            sha512_hash,
            upload_date,
            signature
        )
        VALUES (?, ?, ?, ?)
    """, (
        file.filename,
        document_hash,
        upload_date,
        signature
    ))

    document_id = cursor.lastrowid

    connection.commit()
    connection.close()

    # Save permanent original
    original_path = os.path.join(
        ORIGINAL_FOLDER,
        f"{document_id}_{file.filename}"
    )

    shutil.copy(
        file_path,
        original_path
    )

    return f"""
<!DOCTYPE html>
<html>

<head>

    <title>Document Registered | Secure Document System</title>

    <style>

        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            font-family: "Segoe UI", Arial, sans-serif;
            background: linear-gradient(135deg, #eef4ff, #f8fbff);
            color: #1f2937;
        }}

        .header {{
            background: linear-gradient(135deg, #174ea6, #2563eb);
            color: white;
            padding: 22px 8%;
            box-shadow: 0 4px 15px rgba(37, 99, 235, 0.25);
        }}

        .header h2 {{
            margin: 0;
            font-size: 24px;
        }}

        .header p {{
            margin: 5px 0 0;
            opacity: 0.9;
            font-size: 14px;
        }}

        .container {{
            max-width: 950px;
            margin: 45px auto;
            padding: 0 20px;
        }}

        .success-card {{
            background: white;
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 10px 35px rgba(31, 78, 121, 0.12);
            border: 1px solid #e1eaf7;
        }}

        .success-header {{
            text-align: center;
            margin-bottom: 35px;
        }}

        .success-icon {{
            width: 75px;
            height: 75px;
            margin: auto;
            border-radius: 50%;
            background: #dcfce7;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 38px;
        }}

        .success-header h1 {{
            color: #16803c;
            margin: 18px 0 8px;
            font-size: 30px;
        }}

        .success-header p {{
            color: #64748b;
            margin: 0;
        }}

        .details {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 18px;
            margin-top: 25px;
        }}

        .info-box {{
            background: #f8fbff;
            border: 1px solid #dce7f5;
            border-radius: 12px;
            padding: 18px;
        }}

        .info-label {{
            font-size: 13px;
            color: #64748b;
            margin-bottom: 7px;
        }}

        .info-value {{
            font-size: 16px;
            font-weight: 600;
            color: #1e3a8a;
            word-break: break-word;
        }}

        .security-section {{
            margin-top: 30px;
        }}

        .security-section h3 {{
            color: #174ea6;
            margin-bottom: 10px;
        }}

        .hash,
        .signature {{
            background: #f4f7fb;
            border: 1px solid #dce7f5;
            border-radius: 12px;
            padding: 18px;
            word-break: break-all;
            font-family: Consolas, monospace;
            font-size: 13px;
            line-height: 1.7;
        }}

        .signature-box {{
            border-left: 5px solid #16a34a;
            background: #f0fdf4;
        }}

        .success-message {{
            margin-top: 25px;
            padding: 16px;
            background: #ecfdf5;
            border: 1px solid #bbf7d0;
            border-radius: 10px;
            color: #166534;
            font-weight: 600;
        }}

        .buttons {{
            text-align: center;
            margin-top: 35px;
        }}

        .btn {{
            display: inline-block;
            padding: 13px 24px;
            margin: 5px;
            background: linear-gradient(135deg, #2563eb, #174ea6);
            color: white;
            text-decoration: none;
            border-radius: 10px;
            font-weight: 600;
            transition: 0.2s;
        }}

        .btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 6px 15px rgba(37, 99, 235, 0.25);
        }}

        .history-btn {{
            background: white;
            color: #2563eb;
            border: 2px solid #2563eb;
        }}

        .footer {{
            text-align: center;
            padding: 25px;
            color: #64748b;
            font-size: 13px;
        }}

        @media (max-width: 700px) {{

            .details {{
                grid-template-columns: 1fr;
            }}

            .success-card {{
                padding: 25px;
            }}

            .success-header h1 {{
                font-size: 24px;
            }}

        }}

    </style>

</head>

<body>

    <div class="header">

        <h2>🔐 Secure Document System</h2>

        <p>
            Document Integrity, Tamper Detection & Authentication
        </p>

    </div>


    <div class="container">

        <div class="success-card">

            <div class="success-header">

                <div class="success-icon">
                    
                </div>

                <h1>
                    Document Registered Successfully
                </h1>

                <p>
                    Your document has been securely registered in the system.
                </p>

            </div>


            <div class="details">

                <div class="info-box">

                    <div class="info-label">
                        Document ID
                    </div>

                    <div class="info-value">
                        {document_id}
                    </div>

                </div>


                <div class="info-box">

                    <div class="info-label">
                        File Name
                    </div>

                    <div class="info-value">
                        {file.filename}
                    </div>

                </div>


                <div class="info-box">

                    <div class="info-label">
                        Registration Date
                    </div>

                    <div class="info-value">
                        {upload_date}
                    </div>

                </div>


                <div class="info-box">

                    <div class="info-label">
                        Security Method
                    </div>

                    <div class="info-value">
                        SHA-512 + RSA Signature
                    </div>

                </div>

            </div>


            <div class="security-section">

                <h3> SHA-512 Document Hash</h3>

                <div class="hash">
                    {document_hash}
                </div>

            </div>


            <div class="security-section">

                <h3> Digital Signature</h3>

                <div class="hash signature-box">
                    {signature}
                </div>

            </div>


            <div class="success-message">

                 RSA digital signature created successfully.
                <br>
                Your document is now registered and ready for future verification.

            </div>


            <div class="buttons">

                <a href="/" class="btn">
                     Back to Home
                </a>

                <a href="/history" class="btn history-btn">
                     Verification History
                </a>

            </div>

        </div>

    </div>


    <div class="footer">

        Secure Document Integrity, Tamper Detection & Authentication System
        <br>
        B.Tech Project

    </div>

</body>

</html>
"""


# =========================================================
# VERIFY DOCUMENT
# =========================================================

@app.route("/verify", methods=["POST"])
def verify():

    if "file" not in request.files:

        return "No file uploaded."

    file = request.files["file"]

    if file.filename == "":

        return "No file selected."

    document_id = request.form.get("document_id")

    if not document_id:

        return "Please enter the Document ID."

    # Save current uploaded file
    modified_path = os.path.join(
        UPLOAD_FOLDER,
        f"modified_{file.filename}"
    )

    file.save(modified_path)

    # Generate current hash
    current_hash = generate_sha512(
        modified_path
    )

    # Get registered document
    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            file_name,
            sha512_hash,
            signature
        FROM documents
        WHERE id = ?
    """, (document_id,))

    result = cursor.fetchone()

    connection.close()

    if result is None:

        return """
<!DOCTYPE html>

<html>

<head>

    <title>Document Not Registered</title>

    <style>

        body {{
            font-family: "Segoe UI", Arial, sans-serif;
            background: #eef4fb;
            padding: 40px;
        }}

        .card {{
            background: white;
            padding: 35px;
            border-radius: 16px;
            max-width: 700px;
            margin: auto;
            box-shadow: 0 7px 22px rgba(31,78,121,0.10);
            text-align: center;
        }}

        h1 {{
            color: #dc2626;
        }}

        .btn {{
            display: inline-block;
            margin-top: 20px;
            padding: 12px 20px;
            background: #2563eb;
            color: white;
            text-decoration: none;
            border-radius: 8px;
        }}

    </style>

</head>

<body>

<div class="card">

    <h1> Document Not Registered</h1>

    <p>
        No document was found with the entered Document ID.
    </p>

    <a href="/" class="btn">
        Back to Home
    </a>

</div>

</body>

</html>
"""

    stored_file_name = result[0]
    stored_hash = result[1]
    stored_signature = result[2]

    # Verify digital signature
    signature_valid = verify_digital_signature(
        current_hash,
        stored_signature
    )


    # =====================================================
    # AUTHENTIC
    # =====================================================

    if current_hash == stored_hash:

        if signature_valid:

            save_verification_history(
                document_id,
                stored_file_name,
                "Authentic"
            )

            return f"""
<!DOCTYPE html>

<html>

<head>

    <title>Authentic Document | Secure Document System</title>

    <style>

        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            font-family: "Segoe UI", Arial, sans-serif;
            background: linear-gradient(135deg, #eefaf4, #f8fbff);
            color: #1f2937;
        }}

        .header {{
            background: linear-gradient(135deg, #174ea6, #2563eb);
            color: white;
            padding: 22px 8%;
            box-shadow: 0 4px 15px rgba(37, 99, 235, 0.25);
        }}

        .header h2 {{
            margin: 0;
            font-size: 24px;
        }}

        .header p {{
            margin: 5px 0 0;
            opacity: 0.9;
            font-size: 14px;
        }}

        .container {{
            max-width: 950px;
            margin: 45px auto;
            padding: 0 20px;
        }}

        .card {{
            background: white;
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 10px 35px rgba(31, 78, 121, 0.12);
            border: 1px solid #dcefe5;
        }}

        .status {{
            text-align: center;
            margin-bottom: 35px;
        }}

        .status-icon {{
            width: 75px;
            height: 75px;
            margin: auto;
            border-radius: 50%;
            background: #dcfce7;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 38px;
        }}

        .status h1 {{
            color: #16803c;
            margin: 18px 0 8px;
            font-size: 30px;
        }}

        .status p {{
            color: #64748b;
            margin: 0;
        }}

        .authentic-box {{
            background: #ecfdf5;
            border: 1px solid #bbf7d0;
            border-left: 5px solid #16a34a;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 28px;
        }}

        .authentic-box h2 {{
            color: #16803c;
            margin: 0 0 8px;
            font-size: 22px;
        }}

        .authentic-box p {{
            color: #166534;
            margin: 0;
            line-height: 1.6;
        }}

        .details {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 18px;
        }}

        .info-box {{
            background: #f8fbff;
            border: 1px solid #dce7f5;
            border-radius: 12px;
            padding: 18px;
        }}

        .info-box.full {{
            grid-column: 1 / -1;
        }}

        .info-label {{
            font-size: 13px;
            color: #64748b;
            margin-bottom: 7px;
            font-weight: 600;
        }}

        .info-value {{
            font-size: 16px;
            font-weight: 600;
            color: #1e3a8a;
            word-break: break-word;
        }}

        .hash {{
            background: #f4f7fb;
            border: 1px solid #dce7f5;
            border-radius: 10px;
            padding: 15px;
            word-break: break-all;
            font-family: Consolas, monospace;
            font-size: 13px;
            line-height: 1.7;
            color: #374151;
        }}

        .signature {{
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            border-left: 5px solid #16a34a;
            border-radius: 10px;
            padding: 16px;
            color: #16803c;
            font-weight: 700;
        }}

        .buttons {{
            text-align: center;
            margin-top: 35px;
        }}

        .btn {{
            display: inline-block;
            padding: 13px 24px;
            margin: 5px;
            background: linear-gradient(135deg, #2563eb, #174ea6);
            color: white;
            text-decoration: none;
            border-radius: 10px;
            font-weight: 600;
            transition: 0.2s;
        }}

        .btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 6px 15px rgba(37, 99, 235, 0.25);
        }}

        .history-btn {{
            background: white;
            color: #2563eb;
            border: 2px solid #2563eb;
        }}

        .footer {{
            text-align: center;
            padding: 25px;
            color: #64748b;
            font-size: 13px;
        }}

        @media (max-width: 700px) {{

            .card {{
                padding: 25px;
            }}

            .status h1 {{
                font-size: 24px;
            }}

            .details {{
                grid-template-columns: 1fr;
            }}

            .info-box.full {{
                grid-column: auto;
            }}

        }}

    </style>

</head>

<body>

    <div class="header">

        <h2> Secure Document System</h2>

        <p>
            Document Integrity, Tamper Detection & Authentication
        </p>

    </div>


    <div class="container">

        <div class="card">


            <div class="status">

                <div class="status-icon">
                    
                </div>

                <h1>
                    Document Verified Successfully
                </h1>

                <p>
                    The uploaded document matches the registered document.
                </p>

            </div>


            <div class="authentic-box">

                <h2>
                     Authentic Document
                </h2>

                <p>
                    No unauthorized modification was detected.
                    The RSA digital signature has been successfully verified.
                </p>

            </div>


            <div class="details">


                <div class="info-box">

                    <div class="info-label">
                        Document ID
                    </div>

                    <div class="info-value">
                        {document_id}
                    </div>

                </div>


                <div class="info-box">

                    <div class="info-label">
                        File Name
                    </div>

                    <div class="info-value">
                        {stored_file_name}
                    </div>

                </div>


                <div class="info-box full">

                    <div class="info-label">
                        Stored SHA-512
                    </div>

                    <div class="hash">
                        {stored_hash}
                    </div>

                </div>


                <div class="info-box full">

                    <div class="info-label">
                        Current SHA-512
                    </div>

                    <div class="hash">
                        {current_hash}
                    </div>

                </div>


                <div class="info-box full">

                    <div class="info-label">
                        Digital Signature
                    </div>

                    <div class="signature">
                         VALID — RSA Digital Signature Verified
                    </div>

                </div>


            </div>


            <div class="buttons">

                <a href="/" class="btn">
                     Back to Home
                </a>

                <a href="/history" class="btn history-btn">
                     Verification History
                </a>

            </div>


        </div>

    </div>


    <div class="footer">

        Secure Document Integrity, Tamper Detection & Authentication System
        <br>
        B.Tech Project

    </div>

</body>

</html>
"""

        else:

            save_verification_history(
                document_id,
                stored_file_name,
                "Invalid Signature"
            )

            return f"""
<!DOCTYPE html>

<html>

<head>

    <title>Invalid Signature | Secure Document System</title>

    <style>

        body {{
            margin: 0;
            font-family: "Segoe UI", Arial, sans-serif;
            background: #fff8ed;
            color: #1f2937;
        }}

        .header {{
            background: linear-gradient(135deg, #174ea6, #2563eb);
            color: white;
            padding: 22px 8%;
        }}

        .header h2 {{
            margin: 0;
        }}

        .container {{
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
        }}

        .card {{
            background: white;
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.10);
            border-top: 6px solid #f59e0b;
        }}

        h1 {{
            color: #d97706;
        }}

        .warning {{
            background: #fffbeb;
            border: 1px solid #fde68a;
            border-left: 5px solid #f59e0b;
            padding: 18px;
            border-radius: 10px;
        }}

        .btn {{
            display: inline-block;
            margin-top: 25px;
            padding: 13px 24px;
            background: #2563eb;
            color: white;
            text-decoration: none;
            border-radius: 9px;
        }}

    </style>

</head>

<body>

<div class="header">

    <h2> Secure Document System</h2>

</div>

<div class="container">

<div class="card">

    <h1> Invalid Digital Signature</h1>

    <div class="warning">

        <p>
            The document hash matches the registered document,
            but the digital signature could not be verified.
        </p>

        <p>
            <b>Document ID:</b> {document_id}
        </p>

    </div>

    <a href="/" class="btn">
         Back to Home
    </a>

    <a href="/history" class="btn">
         Verification History
    </a>

</div>

</div>

</body>

</html>
"""


    # =====================================================
    # TAMPERED
    # =====================================================

    else:

        save_verification_history(
            document_id,
            stored_file_name,
            "Tampered"
        )

        original_path = os.path.join(
            ORIGINAL_FOLDER,
            f"{document_id}_{stored_file_name}"
        )

        changes_html = ""

        # Word document comparison
        if (
            stored_file_name.lower().endswith(".docx")
            and os.path.exists(original_path)
        ):

            changes = compare_word_documents(
                original_path,
                modified_path
            )

            if changes:

                changes_html += """
                <h2> Modification Details</h2>
                """

                for change_type, original, modified in changes:

                    if change_type == "replace":

                        for old, new in zip(
                            original,
                            modified
                        ):

                            changes_html += f"""
                            <div style="
                                background:#fff3cd;
                                padding:15px;
                                margin:10px 0;
                                border-radius:8px;
                                border-left:5px solid #f59e0b;
                            ">

                            <p>
                            <b>Original:</b> {old}
                            </p>

                            <p>
                            <b>Modified:</b> {new}
                            </p>

                            </div>
                            """

                    elif change_type == "delete":

                        for old in original:

                            changes_html += f"""
                            <div style="
                                background:#f8d7da;
                                padding:15px;
                                margin:10px 0;
                                border-radius:8px;
                                border-left:5px solid #dc3545;
                            ">

                            <b>Deleted:</b> {old}

                            </div>
                            """

                    elif change_type == "insert":

                        for new in modified:

                            changes_html += f"""
                            <div style="
                                background:#d1ecf1;
                                padding:15px;
                                margin:10px 0;
                                border-radius:8px;
                                border-left:5px solid #0f766e;
                            ">

                            <b>Added:</b> {new}

                            </div>
                            """

            else:

                changes_html = """
                <p>
                No detailed text changes could be displayed.
                </p>
                """

        else:

            changes_html = """
            <p>
            Detailed modification comparison is currently available
            for Word (.docx) documents.
            </p>
            """


        return f"""
<!DOCTYPE html>

<html>

<head>

    <title>Tampered Document | Secure Document System</title>

    <style>

        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            font-family: "Segoe UI", Arial, sans-serif;
            background: linear-gradient(135deg, #fff5f5, #f8fbff);
            color: #1f2937;
        }}

        .header {{
            background: linear-gradient(135deg, #174ea6, #2563eb);
            color: white;
            padding: 22px 8%;
            box-shadow: 0 4px 15px rgba(37, 99, 235, 0.25);
        }}

        .header h2 {{
            margin: 0;
            font-size: 24px;
        }}

        .header p {{
            margin: 5px 0 0;
            opacity: 0.9;
            font-size: 14px;
        }}

        .container {{
            max-width: 950px;
            margin: 45px auto;
            padding: 0 20px;
        }}

        .card {{
            background: white;
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 10px 35px rgba(31, 78, 121, 0.12);
            border: 1px solid #e1eaf7;
        }}

        .status {{
            text-align: center;
            margin-bottom: 35px;
        }}

        .status-icon {{
            width: 75px;
            height: 75px;
            margin: auto;
            border-radius: 50%;
            background: #fee2e2;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 38px;
        }}

        .status h1 {{
            color: #dc2626;
            margin: 18px 0 8px;
            font-size: 30px;
        }}

        .status p {{
            color: #64748b;
            margin: 0;
        }}

        .file-box {{
            background: #f8fbff;
            border: 1px solid #dce7f5;
            border-radius: 12px;
            padding: 18px;
            margin-bottom: 25px;
        }}

        .file-label {{
            font-size: 13px;
            color: #64748b;
            margin-bottom: 6px;
        }}

        .file-name {{
            font-weight: 600;
            color: #1e3a8a;
            font-size: 17px;
            word-break: break-word;
        }}

        .section {{
            margin-top: 28px;
        }}

        .section h3 {{
            color: #174ea6;
            margin-bottom: 10px;
        }}

        .hash {{
            background: #f4f7fb;
            border: 1px solid #dce7f5;
            border-radius: 12px;
            padding: 18px;
            word-break: break-all;
            font-family: Consolas, monospace;
            font-size: 13px;
            line-height: 1.7;
        }}

        .signature-error {{
            margin-top: 28px;
            padding: 18px;
            background: #fff1f2;
            border: 1px solid #fecdd3;
            border-left: 5px solid #dc2626;
            border-radius: 12px;
        }}

        .signature-error h2 {{
            color: #dc2626;
            margin-top: 0;
            font-size: 21px;
        }}

        .signature-error p {{
            margin-bottom: 0;
            color: #4b5563;
            line-height: 1.6;
        }}

        .modifications {{
            margin-top: 30px;
            padding: 22px;
            background: #fffaf0;
            border: 1px solid #fde68a;
            border-radius: 14px;
        }}

        .modifications h2 {{
            color: #b45309;
            margin-top: 0;
        }}

        .buttons {{
            text-align: center;
            margin-top: 35px;
        }}

        .btn {{
            display: inline-block;
            padding: 13px 24px;
            margin: 5px;
            background: linear-gradient(135deg, #2563eb, #174ea6);
            color: white;
            text-decoration: none;
            border-radius: 10px;
            font-weight: 600;
            transition: 0.2s;
        }}

        .btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 6px 15px rgba(37, 99, 235, 0.25);
        }}

        .history-btn {{
            background: white;
            color: #2563eb;
            border: 2px solid #2563eb;
        }}

        .footer {{
            text-align: center;
            padding: 25px;
            color: #64748b;
            font-size: 13px;
        }}

        @media (max-width: 700px) {{

            .card {{
                padding: 25px;
            }}

            .status h1 {{
                font-size: 24px;
            }}

        }}

    </style>

</head>

<body>

    <div class="header">

        <h2> Secure Document System</h2>

        <p>
            Document Integrity, Tamper Detection & Authentication
        </p>

    </div>


    <div class="container">

        <div class="card">


            <div class="status">

                <div class="status-icon">
                    
                </div>

                <h1>
                     Document is Tampered
                </h1>

                <p>
                    Changes were detected in the submitted document.
                </p>

            </div>


            <div class="file-box">

                <div class="file-label">
                    Registered File
                </div>

                <div class="file-name">
                    {stored_file_name}
                </div>

            </div>


            <div class="section">

                <h3>
                     Stored SHA-512
                </h3>

                <div class="hash">
                    {stored_hash}
                </div>

            </div>


            <div class="section">

                <h3>
                    🔍 Current SHA-512
                </h3>

                <div class="hash">
                    {current_hash}
                </div>

            </div>


            <div class="signature-error">

                <h2>
                     Invalid Digital Signature
                </h2>

                <p>
                    The RSA public key could not verify the original
                    digital signature against the current document.
                </p>

            </div>


            <div class="modifications">

                {changes_html}

            </div>


            <div class="buttons">

                <a href="/" class="btn">
                     Back to Home
                </a>

                <a href="/history" class="btn history-btn">
                     Verification History
                </a>

            </div>


        </div>

    </div>


    <div class="footer">

        Secure Document Integrity, Tamper Detection & Authentication System
        <br>
        B.Tech Project

    </div>

</body>

</html>
"""


# =========================================================
# VERIFICATION HISTORY
# =========================================================

@app.route("/history")
def verification_history():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            document_id,
            file_name,
            verification_result,
            verification_date
        FROM verification_history
        ORDER BY id DESC
    """)

    history = cursor.fetchall()

    connection.close()

    rows = ""

    if history:

        for record in history:

            document_id = record[0]
            file_name = record[1]
            result = record[2]
            verification_date = record[3]

            if result == "Authentic":

                result_display = """
                <span style="
                    color:#16803c;
                    font-weight:bold;
                ">
                     Authentic
                </span>
                """

            elif result == "Tampered":

                result_display = """
                <span style="
                    color:#dc2626;
                    font-weight:bold;
                ">
                     Tampered
                </span>
                """

            else:

                result_display = f"""
                <span style="
                    color:#d97706;
                    font-weight:bold;
                ">
                     {result}
                </span>
                """

            rows += f"""
            <tr>

                <td>{document_id}</td>

                <td>{file_name}</td>

                <td>{result_display}</td>

                <td>{verification_date}</td>

            </tr>
            """

    else:

        rows = """
        <tr>

            <td colspan="4">
                No verification history available yet.
            </td>

        </tr>
        """

    return f"""
<!DOCTYPE html>

<html>

<head>

<title>Verification History</title>

<style>

body {{
    font-family: "Segoe UI", Arial, sans-serif;
    background: #eef4fb;
    padding: 40px;
}}

.container {{
    max-width: 1000px;
    margin: auto;
}}

.card {{
    background: white;
    padding: 35px;
    border-radius: 16px;
    box-shadow: 0 7px 22px rgba(31,78,121,0.10);
}}

h1 {{
    color: #174ea6;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 25px;
}}

th {{
    background: #2563eb;
    color: white;
    padding: 14px;
    text-align: left;
}}

td {{
    padding: 14px;
    border-bottom: 1px solid #dce7f5;
}}

tr:hover {{
    background: #f5f8fc;
}}

.btn {{
    display: inline-block;
    margin-top: 25px;
    padding: 12px 20px;
    background: #2563eb;
    color: white;
    text-decoration: none;
    border-radius: 8px;
}}

</style>

</head>

<body>

<div class="container">

<div class="card">

<h1>
 Verification History
</h1>

<p>
Previous security checks performed on your documents.
</p>

<table>

<tr>

<th>Document ID</th>

<th>File Name</th>

<th>Verification Result</th>

<th>Verification Date</th>

</tr>

{rows}

</table>

<a href="/" class="btn">
Back to Home
</a>

</div>

</div>

</body>

</html>
"""


# =========================================================
# RUN FLASK
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )