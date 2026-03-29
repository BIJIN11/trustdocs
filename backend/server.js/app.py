from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from pymongo import MongoClient
from datetime import datetime
from werkzeug.utils import secure_filename
import os
import base64
from bson import ObjectId
import hashlib
import random
import qrcode5
from io import BytesIO
import json
from PIL import Image, ImageDraw, ImageFont
import io

app = Flask(__name__)
CORS(app)  # Allow frontend to connect

# Configuration
UPLOAD_FOLDER = 'uploads'
QR_FOLDER = 'qrcodes'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['QR_FOLDER'] = QR_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['BASE_URL'] = 'http://10.192.33.184:5000'  # Use your Wi-Fi IP

# Ensure folders exist
for folder in [UPLOAD_FOLDER, QR_FOLDER]:
    if not os.path.exists(folder):
        os.makedirs(folder)

# Connect to MongoDB
try:
    client = MongoClient('mongodb://127.0.0.1:27017/')
    db = client['trustdocs']
    users_collection = db['users']
    documents_collection = db['documents']
    print("✅ Connected to MongoDB successfully")
except Exception as e:
    print(f"❌ MongoDB connection error: {e}")


# Helper function to hash password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# Helper function to check if password is hashed (64 character hex string)
def is_hashed(password):
    return len(password) == 64 and all(c in '0123456789abcdef' for c in password.lower())


# Helper function to verify password (works with both plain and hashed)
def verify_password(plain_password, stored_password):
    # If stored password is hashed
    if is_hashed(stored_password):
        return stored_password == hash_password(plain_password)
    else:
        # Plain text comparison for old data
        return stored_password == plain_password


# Helper function to convert ObjectId to string
def parse_json(data):
    if isinstance(data, list):
        for item in data:
            item['_id'] = str(item['_id'])
        return data
    elif isinstance(data, dict):
        data['_id'] = str(data['_id'])
        return data
    return data


# ==================== HELPER FUNCTION TO EMBED QR IN DOCUMENT ====================
def embed_qr_in_document(document_data, qr_image, mime_type):
    """
    Embeds QR code into the document based on file type
    Returns modified document data as base64
    """
    try:
        if mime_type.startswith('image/'):
            # For images, overlay QR code at bottom right
            # Decode base64 image
            img_data = base64.b64decode(document_data)
            img = Image.open(io.BytesIO(img_data))

            # Resize QR to be 15% of image width
            qr_size = int(img.width * 0.15)
            qr_resized = qr_image.resize((qr_size, qr_size), Image.Resampling.LANCZOS)

            # Create a copy of the original image
            img_copy = img.copy()

            # Calculate position (bottom right with 10px padding)
            position = (img.width - qr_size - 10, img.height - qr_size - 10)

            # Paste QR code
            if img_copy.mode == 'RGB':
                img_copy.paste(qr_resized, position)
            else:
                # Handle RGBA images
                if qr_resized.mode != 'RGBA':
                    qr_resized = qr_resized.convert('RGBA')
                img_copy.paste(qr_resized, position, qr_resized)

            # Convert back to base64
            img_byte_arr = io.BytesIO()
            img_copy.save(img_byte_arr, format=img.format or 'PNG')
            img_byte_arr = img_byte_arr.getvalue()
            return base64.b64encode(img_byte_arr).decode('utf-8')

        elif mime_type == 'application/pdf':
            # For PDFs, we'll add QR as an attachment or watermark
            # Note: This is a simplified version - for production, use PyPDF2 or reportlab
            print("PDF QR embedding - keeping QR separate for now")
            return document_data

        else:
            # For other files, keep QR separate
            return document_data

    except Exception as e:
        print(f"Error embedding QR: {e}")
        return document_data


# ==================== TEST CONNECTION ====================
@app.route('/')
def home():
    return jsonify({"message": "TrustDocs Backend Running", "status": "connected"})


@app.route('/api/test')
def test_api():
    # Count users to verify database connection
    user_count = users_collection.count_documents({})
    return jsonify({
        "status": "working",
        "message": "Python backend is ready!",
        "database": "Connected to MongoDB",
        "users_in_db": user_count
    })


# ==================== USER REGISTRATION ====================
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role', 'student')
        institution = data.get('institution', 'Not provided')

        # Validation
        if not username or not email or not password:
            return jsonify({"message": "Username, email, and password are required"}), 400

        # Check if user exists
        if users_collection.find_one({"$or": [{"email": email}, {"username": username}]}):
            return jsonify({"message": "Username or email already registered"}), 400

        # NEW USERS: Store with hashed password
        new_user = {
            "username": username,
            "email": email,
            "password": hash_password(password),  # HASHED for new users
            "role": role,
            "institution": institution,
            "fullName": "",
            "createdAt": datetime.now(),
            "updatedAt": datetime.now(),
            "password_type": "hashed"  # Optional: track password type
        }

        result = users_collection.insert_one(new_user)

        return jsonify({
            "message": "Registration successful! Please log in.",
            "userId": str(result.inserted_id)
        }), 201

    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({"message": f"Server error: {str(e)}"}), 500


# ==================== USER LOGIN ====================
@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({"message": "Username and password required"}), 400

        # Find user
        user = users_collection.find_one({"username": username})

        if not user:
            return jsonify({"message": "Invalid username or password"}), 401

        # Get stored password
        stored_password = user.get('password', '')

        # Check if password matches (works for both plain and hashed)
        if not verify_password(password, stored_password):
            return jsonify({"message": "Invalid username or password"}), 401

        # OPTIONAL: If user logged in with plain text password,
        # we could upgrade them to hashed automatically
        if not is_hashed(stored_password):
            # This user still has plain text password - upgrade to hashed
            users_collection.update_one(
                {'_id': user['_id']},
                {'$set': {
                    'password': hash_password(password),
                    'password_type': 'upgraded_to_hashed',
                    'upgraded_at': datetime.now()
                }}
            )
            print(f"🔄 Upgraded user {username} from plain to hashed password")

        # Return user info (without password)
        response_user = {
            "username": user["username"],
            "email": user.get("email", ""),
            "role": user.get("role", "student"),
            "institution": user.get("institution", "")
        }

        return jsonify({
            "message": "Login successful",
            "user": response_user
        }), 200

    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({"message": f"Server error: {str(e)}"}), 500


# ==================== ISSUER REGISTRATION ====================
@app.route('/api/register-issuer', methods=['POST'])
def register_issuer():
    try:
        data = request.json
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        institution = data.get('institution')

        if not username or not email or not password or not institution:
            return jsonify({"message": "All fields are required"}), 400

        if users_collection.find_one({"$or": [{"email": email}, {"username": username}]}):
            return jsonify({"message": "Username or email already registered"}), 400

        # NEW ISSUERS: Store with hashed password
        new_issuer = {
            "username": username,
            "email": email,
            "password": hash_password(password),  # HASHED for new issuers
            "role": "issuer",
            "institution": institution,
            "fullName": "",
            "createdAt": datetime.now(),
            "updatedAt": datetime.now(),
            "password_type": "hashed"
        }

        result = users_collection.insert_one(new_issuer)

        return jsonify({
            "message": "Issuer account created successfully!",
            "userId": str(result.inserted_id)
        }), 201

    except Exception as e:
        print(f"Issuer registration error: {e}")
        return jsonify({"message": f"Server error: {str(e)}"}), 500


# ==================== ISSUER LOGIN ====================
@app.route('/api/login-issuer', methods=['POST'])
def login_issuer():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({"message": "Username and password required"}), 400

        user = users_collection.find_one({"username": username, "role": "issuer"})

        if not user:
            return jsonify({"message": "Invalid username or password"}), 401

        # Get stored password
        stored_password = user.get('password', '')

        # Check if password matches (works for both plain and hashed)
        if not verify_password(password, stored_password):
            return jsonify({"message": "Invalid username or password"}), 401

        # OPTIONAL: Upgrade plain text passwords to hashed
        if not is_hashed(stored_password):
            users_collection.update_one(
                {'_id': user['_id']},
                {'$set': {
                    'password': hash_password(password),
                    'password_type': 'upgraded_to_hashed',
                    'upgraded_at': datetime.now()
                }}
            )
            print(f"🔄 Upgraded issuer {username} from plain to hashed password")

        response_user = {
            "username": user["username"],
            "email": user.get("email", ""),
            "role": user["role"],
            "institution": user.get("institution", "")
        }

        return jsonify({
            "message": "Login successful",
            "user": response_user
        }), 200

    except Exception as e:
        print(f"Issuer login error: {e}")
        return jsonify({"message": f"Server error: {str(e)}"}), 500


# ==================== UPDATE STUDENT DETAILS ====================
@app.route('/api/update-student-details', methods=['POST'])
def update_student_details():
    try:
        data = request.json
        username = data.get('username')
        fullName = data.get('fullName')
        email = data.get('email')
        institution = data.get('institution')

        if not username or not fullName or not email or not institution:
            return jsonify({"message": "All fields are required"}), 400

        result = users_collection.update_one(
            {"username": username},
            {
                "$set": {
                    "fullName": fullName,
                    "email": email,
                    "institution": institution,
                    "updatedAt": datetime.now()
                }
            }
        )

        if result.matched_count == 0:
            return jsonify({"message": "User not found"}), 404

        return jsonify({"message": "Details updated successfully"}), 200

    except Exception as e:
        print(f"Update details error: {e}")
        return jsonify({"message": f"Server error: {str(e)}"}), 500


# ==================== UPLOAD STUDENT DOCUMENT ====================
@app.route('/api/upload-document', methods=['POST'])
def upload_document():
    try:
        # Get form data
        student_username = request.form.get('username')
        document_type = request.form.get('documentType')
        full_name = request.form.get('fullName', '')
        email = request.form.get('email', '')
        institution = request.form.get('institution', '')

        # Validation
        if not student_username or not document_type:
            return jsonify({"message": "Username and document type are required"}), 400

        # Check file
        if 'file' not in request.files:
            return jsonify({"message": "No file uploaded"}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({"message": "No file selected"}), 400

        # Secure filename and save
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_filename = f"{timestamp}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

        file.save(file_path)

        # Read file as base64 for storage/retrieval
        with open(file_path, 'rb') as f:
            file_data = base64.b64encode(f.read()).decode('utf-8')
            print(f"📁 File saved: {filename}")
            print(f"📊 File size: {os.path.getsize(file_path)} bytes")
            print(f"🔐 Base64 length: {len(file_data)} characters")

        # Create document record
        document = {
            "studentUsername": student_username,
            "fullName": full_name,
            "email": email,
            "institution": institution,
            "documentType": document_type,
            "documentName": filename,
            "fileName": unique_filename,
            "fileData": file_data,
            "fileMetadata": {
                "mimeType": file.content_type,
                "size": os.path.getsize(file_path)
            },
            "status": "pending",
            "uploadedAt": datetime.now(),
            "verifiedBy": None,
            "verifiedAt": None,
            "aiScore": None,
            "aiAnalysis": None,
            "qrCode": None,
            "verificationUrl": None,
            "hasEmbeddedQR": False
        }

        result = documents_collection.insert_one(document)

        return jsonify({
            "message": "Document uploaded successfully",
            "documentId": str(result.inserted_id)
        }), 201

    except Exception as e:
        print(f"Upload error: {e}")
        return jsonify({"message": f"Server error: {str(e)}"}), 500


# ==================== ISSUE DOCUMENT ====================
@app.route('/api/issue-document', methods=['POST'])
def issue_document():
    try:
        issuer_name = request.form.get('issuerName')
        issuer_email = request.form.get('issuerEmail')
        issuer_institution = request.form.get('issuerInstitution')
        issuer_document_type = request.form.get('issuerDocumentType')
        issuer_username = request.form.get('issuerUsername')

        if not all([issuer_name, issuer_email, issuer_institution, issuer_document_type, issuer_username]):
            return jsonify({"message": "All fields are required"}), 400

        if 'file' not in request.files:
            return jsonify({"message": "No file uploaded"}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({"message": "No file selected"}), 400

        # Save file
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_filename = f"ISSUED_{timestamp}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)

        # Read file as base64
        with open(file_path, 'rb') as f:
            file_data = base64.b64encode(f.read()).decode('utf-8')

        # Create issued document
        document = {
            "issuerUsername": issuer_username,
            "issuerName": issuer_name,
            "issuerEmail": issuer_email,
            "issuerInstitution": issuer_institution,
            "documentType": issuer_document_type,
            "documentName": filename,
            "fileName": unique_filename,
            "fileData": file_data,
            "fileMetadata": {
                "mimeType": file.content_type,
                "size": os.path.getsize(file_path)
            },
            "status": "issued",
            "issuedAt": datetime.now()
        }

        result = documents_collection.insert_one(document)

        return jsonify({
            "message": "Document issued successfully",
            "documentId": str(result.inserted_id)
        }), 201

    except Exception as e:
        print(f"Issue document error: {e}")
        return jsonify({"message": f"Server error: {str(e)}"}), 500


# ==================== GET STUDENT DOCUMENTS ====================
@app.route('/api/student-documents', methods=['GET'])
def student_documents():
    try:
        username = request.args.get('username')
        if not username:
            return jsonify({"message": "Username required"}), 400

        documents = list(documents_collection.find(
            {"studentUsername": username},
            {"fileData": 0}  # Exclude file data for list view
        ).sort("uploadedAt", -1))

        formatted_docs = []
        for doc in documents:
            formatted_docs.append({
                "_id": str(doc["_id"]),
                "documentType": doc.get("documentType", "Unknown"),
                "documentName": doc.get("documentName", "No name"),
                "status": doc.get("status", "pending").capitalize(),
                "uploadedAt": doc.get("uploadedAt", "").strftime("%Y-%m-%d %H:%M") if doc.get("uploadedAt") else "",
                "hasQR": doc.get("qrCode") is not None,
                "hasEmbeddedQR": doc.get("hasEmbeddedQR", False)
            })

        return jsonify({"documents": formatted_docs}), 200

    except Exception as e:
        print(f"Get student documents error: {e}")
        return jsonify({"message": f"Server error: {str(e)}"}), 500


# ==================== GET PENDING DOCUMENTS (for issuer) ====================
@app.route('/api/pending-documents', methods=['GET'])
def pending_documents():
    try:
        institution = request.args.get('institution')
        if not institution:
            return jsonify({"message": "Institution required"}), 400

        documents = list(documents_collection.find(
            {
                "institution": institution,
                "status": "pending"
            },
            {"fileData": 0}  # Exclude file data for list view
        ).sort("uploadedAt", -1))

        formatted_docs = []
        for doc in documents:
            formatted_docs.append({
                "_id": str(doc["_id"]),
                "studentUsername": doc.get("studentUsername", "Unknown"),
                "fullName": doc.get("fullName", ""),
                "documentType": doc.get("documentType", "Unknown"),
                "documentName": doc.get("documentName", "No name"),
                "uploadedAt": doc.get("uploadedAt", "").strftime("%Y-%m-%d %H:%M") if doc.get("uploadedAt") else ""
            })

        return jsonify({"documents": formatted_docs}), 200

    except Exception as e:
        print(f"Get pending documents error: {e}")
        return jsonify({"message": f"Server error: {str(e)}"}), 500


# ==================== GET SINGLE DOCUMENT (with file) ====================
@app.route('/api/get-document', methods=['GET'])
def get_document():
    try:
        document_id = request.args.get('documentId')
        if not document_id:
            return jsonify({"message": "Document ID required"}), 400

        document = documents_collection.find_one({"_id": ObjectId(document_id)})

        if not document:
            return jsonify({"message": "Document not found"}), 404

        # Convert ObjectId to string
        document['_id'] = str(document['_id'])

        return jsonify({"document": document}), 200

    except Exception as e:
        print(f"Get document error: {e}")
        return jsonify({"message": f"Server error: {str(e)}"}), 500


# ==================== GET ORIGINAL DOCUMENT (without QR) ====================
@app.route('/api/get-original-document/<document_id>', methods=['GET'])
def get_original_document(document_id):
    """Get document without QR code embedded"""
    try:
        if not ObjectId.is_valid(document_id):
            return jsonify({"message": "Invalid document ID"}), 400

        document = documents_collection.find_one({"_id": ObjectId(document_id)})

        if not document:
            return jsonify({"message": "Document not found"}), 404

        # Check if we have original stored
        if document.get('originalFileData'):
            document['fileData'] = document['originalFileData']
            document['_id'] = str(document['_id'])
            return jsonify({"document": document}), 200
        else:
            # Return as is
            document['_id'] = str(document['_id'])
            return jsonify({"document": document}), 200

    except Exception as e:
        print(f"Get original document error: {e}")
        return jsonify({"message": f"Server error: {str(e)}"}), 500


# ==================== GENERATE QR CODE FOR VERIFIED DOCUMENT ====================
@app.route('/api/generate-qr/<document_id>', methods=['POST'])
def generate_qr(document_id):
    try:
        if not ObjectId.is_valid(document_id):
            return jsonify({"message": "Invalid document ID"}), 400

        document = documents_collection.find_one({"_id": ObjectId(document_id)})

        if not document:
            return jsonify({"message": "Document not found"}), 404

        # Only generate QR for valid documents
        if document.get('status') != 'valid':
            return jsonify({"message": "QR codes can only be generated for valid documents"}), 400

        # Create verification URL
        verification_url = f"{app.config['BASE_URL']}/api/verify-document-qr/{document_id}"

        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(verification_url)
        qr.make(fit=True)

        qr_img = qr.make_image(fill_color="black", back_color="white")

        # Save QR code to file (keep original for reference)
        qr_filename = f"qr_{document_id}.png"
        qr_path = os.path.join(app.config['QR_FOLDER'], qr_filename)
        qr_img.save(qr_path)

        # Convert QR to base64
        with open(qr_path, 'rb') as f:
            qr_base64 = base64.b64encode(f.read()).decode('utf-8')

        # Get original document data
        file_data = document.get('fileData')
        mime_type = document.get('fileMetadata', {}).get('mimeType', 'application/octet-stream')

        # Embed QR in document
        modified_file_data = embed_qr_in_document(file_data, qr_img, mime_type)

        # Update document with QR info and modified file
        update_data = {
            "qrCode": qr_base64,
            "qrPath": qr_path,
            "verificationUrl": verification_url,
            "qrGeneratedAt": datetime.now(),
            "hasEmbeddedQR": modified_file_data != file_data
        }

        # If QR was embedded, update the file data and store original
        if modified_file_data != file_data:
            update_data["fileData"] = modified_file_data
            update_data["originalFileData"] = file_data
            update_data["hasEmbeddedQR"] = True

        documents_collection.update_one(
            {"_id": ObjectId(document_id)},
            {"$set": update_data}
        )

        return jsonify({
            "message": "QR code generated and embedded in document",
            "qrCode": qr_base64,
            "verificationUrl": verification_url,
            "embedded": modified_file_data != file_data
        }), 200

    except Exception as e:
        print(f"QR generation error: {e}")
        return jsonify({"message": f"Server error: {str(e)}"}), 500


# ==================== VERIFY DOCUMENT VIA QR ====================
@app.route('/api/verify-document-qr/<document_id>', methods=['GET'])
def verify_document_qr(document_id):
    try:
        if not ObjectId.is_valid(document_id):
            return jsonify({"message": "Invalid document ID"}), 400

        document = documents_collection.find_one({"_id": ObjectId(document_id)})

        if not document:
            return jsonify({"message": "Document not found"}), 404

        # Check if document is valid
        if document.get('status') != 'valid':
            return jsonify({
                "verified": False,
                "message": "This document has not been verified",
                "status": document.get('status')
            }), 200

        # Return verification info
        return jsonify({
            "verified": True,
            "message": "✅ TRUSTDOCS VERIFIED",
            "documentName": document.get('documentName'),
            "studentName": document.get('fullName'),
            "institution": document.get('institution'),
            "documentType": document.get('documentType'),
            "verifiedBy": document.get('verifiedBy'),
            "verifiedAt": document.get('verifiedAt').strftime("%Y-%m-%d %H:%M:%S") if document.get(
                'verifiedAt') else None,
            "aiScore": document.get('aiScore'),
            "hasEmbeddedQR": document.get('hasEmbeddedQR', False)
        }), 200

    except Exception as e:
        print(f"QR verification error: {e}")
        return jsonify({"message": f"Server error: {str(e)}"}), 500


# ==================== UPDATE DOCUMENT STATUS (issuer verification) ====================
@app.route('/api/update-document-status', methods=['POST'])
def update_document_status():
    try:
        data = request.json
        document_id = data.get('documentId')
        status = data.get('status')
        issuer_username = data.get('issuerUsername')

        if not all([document_id, status, issuer_username]):
            return jsonify({"message": "All fields required"}), 400

        # Generate AI analysis (simulated)
        ai_score = random.randint(70, 100)
        ai_analysis = {
            "score": ai_score,
            "confidence": "High" if ai_score > 85 else "Medium",
            "checks": ["Format validation", "Digital signature", "Content analysis"],
            "timestamp": datetime.now().isoformat()
        }

        result = documents_collection.update_one(
            {"_id": ObjectId(document_id)},
            {
                "$set": {
                    "status": status,
                    "verifiedBy": issuer_username,
                    "verifiedAt": datetime.now(),
                    "aiScore": ai_score,
                    "aiAnalysis": ai_analysis
                }
            }
        )

        if result.matched_count == 0:
            return jsonify({"message": "Document not found"}), 404

        # If document is marked as valid, generate and embed QR code
        if status == 'valid':
            try:
                document = documents_collection.find_one({"_id": ObjectId(document_id)})
                verification_url = f"{app.config['BASE_URL']}/api/verify-document-qr/{document_id}"

                # Generate QR
                qr = qrcode.QRCode(version=1, box_size=10, border=5)
                qr.add_data(verification_url)
                qr.make(fit=True)
                qr_img = qr.make_image(fill_color="black", back_color="white")

                # Save QR
                qr_filename = f"qr_{document_id}.png"
                qr_path = os.path.join(app.config['QR_FOLDER'], qr_filename)
                qr_img.save(qr_path)

                with open(qr_path, 'rb') as f:
                    qr_base64 = base64.b64encode(f.read()).decode('utf-8')

                # Embed QR in document
                file_data = document.get('fileData')
                mime_type = document.get('fileMetadata', {}).get('mimeType', 'application/octet-stream')
                modified_file_data = embed_qr_in_document(file_data, qr_img, mime_type)

                # Update with QR and embedded file
                update_data = {
                    "qrCode": qr_base64,
                    "qrPath": qr_path,
                    "verificationUrl": verification_url,
                    "qrGeneratedAt": datetime.now()
                }

                if modified_file_data != file_data:
                    update_data["fileData"] = modified_file_data
                    update_data["originalFileData"] = file_data
                    update_data["hasEmbeddedQR"] = True

                documents_collection.update_one(
                    {"_id": ObjectId(document_id)},
                    {"$set": update_data}
                )

            except Exception as qr_error:
                print(f"QR generation error (non-critical): {qr_error}")

        return jsonify({
            "message": f"Document marked as {status}",
            "aiScore": ai_score
        }), 200

    except Exception as e:
        print(f"Update status error: {e}")
        return jsonify({"message": f"Server error: {str(e)}"}), 500


# ==================== VERIFY DOCUMENT (verifier role) ====================
@app.route('/api/verify-document', methods=['POST'])
def verify_document():
    try:
        data = request.json
        original_name = data.get('originalName')
        mime_type = data.get('mimeType')
        size_bytes = data.get('sizeBytes')

        # Simulate AI verification
        score = random.randint(65, 100)

        # Check against database (simplified)
        similar_docs = documents_collection.count_documents({
            "fileMetadata.mimeType": mime_type,
            "status": "valid"
        })

        result_text = "GENUINE" if score >= 80 else "SUSPICIOUS" if score >= 60 else "FAKE"

        details = f"File: {original_name}\nType: {mime_type}\nSize: {size_bytes} bytes\nSimilar valid docs found: {similar_docs}"

        return jsonify({
            "score": score,
            "result": result_text,
            "details": details,
            "verified": score >= 75
        }), 200

    except Exception as e:
        print(f"Verify document error: {e}")
        return jsonify({"message": f"Server error: {str(e)}"}), 500


# ==================== DEBUG: LIST ALL USERS (with password type) ====================
@app.route('/api/users', methods=['GET'])
def list_users():
    try:
        users = list(users_collection.find({}, {"password": 1, "username": 1, "role": 1, "email": 1}))
        for user in users:
            user['_id'] = str(user['_id'])
            # Add password type info for debugging
            if is_hashed(user.get('password', '')):
                user['password_type'] = 'hashed'
                user['password'] = '[HASHED]'
            else:
                user['password_type'] = 'plain'
                user['password'] = '[PLAIN]'
        return jsonify({"users": users}), 200
    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}"}), 500


# ==================== DEBUG: CHECK DOCUMENT STORAGE ====================
@app.route('/api/debug-document/<document_id>', methods=['GET'])
def debug_document(document_id):
    try:
        if not ObjectId.is_valid(document_id):
            return jsonify({"error": "Invalid document ID format"}), 400

        document = documents_collection.find_one({"_id": ObjectId(document_id)})

        if not document:
            return jsonify({"error": "Document not found"}), 404

        # Create a safe version for debugging (exclude large file data if needed)
        debug_info = {
            "id": str(document['_id']),
            "documentName": document.get('documentName'),
            "documentType": document.get('documentType'),
            "studentUsername": document.get('studentUsername'),
            "status": document.get('status'),
            "hasFileData": 'fileData' in document,
            "fileDataLength": len(document.get('fileData', '')) if document.get('fileData') else 0,
            "hasQR": document.get('qrCode') is not None,
            "hasEmbeddedQR": document.get('hasEmbeddedQR', False),
            "fileMetadata": document.get('fileMetadata'),
            "uploadedAt": str(document.get('uploadedAt')) if document.get('uploadedAt') else None
        }

        return jsonify(debug_info), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==================== TEST DOCUMENT RETRIEVAL ====================
@app.route('/api/test-document-retrieval', methods=['GET'])
def test_document_retrieval():
    """Test endpoint to see all documents and their file data status"""
    try:
        documents = list(documents_collection.find({}, {
            "documentName": 1,
            "studentUsername": 1,
            "status": 1,
            "fileMetadata": 1,
            "uploadedAt": 1,
            "qrCode": 1,
            "hasEmbeddedQR": 1
        }).limit(10))

        for doc in documents:
            doc['_id'] = str(doc['_id'])
            # Check if file exists on disk
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], doc.get('fileName', ''))
            doc['fileExistsOnDisk'] = os.path.exists(file_path) if doc.get('fileName') else False
            doc['hasQR'] = doc.get('qrCode') is not None

        return jsonify({
            "total_documents": documents_collection.count_documents({}),
            "documents": documents
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==================== FIX: GENERATE QR FOR EXISTING VALID DOCUMENTS ====================
@app.route('/api/fix-qr/<document_id>', methods=['GET', 'POST'])
def fix_qr(document_id):
    try:
        if not ObjectId.is_valid(document_id):
            return jsonify({"message": "Invalid document ID"}), 400

        document = documents_collection.find_one({"_id": ObjectId(document_id)})

        if not document:
            return jsonify({"message": "Document not found"}), 404

        # Check if document is valid
        if document.get('status') != 'valid':
            return jsonify({"message": "Document is not valid"}), 400

        print(f"Generating QR for document: {document_id}")

        # Generate QR code
        verification_url = f"{app.config['BASE_URL']}/api/verify-document-qr/{document_id}"

        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(verification_url)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white")

        # Ensure QR folder exists
        if not os.path.exists(app.config['QR_FOLDER']):
            os.makedirs(app.config['QR_FOLDER'])

        qr_filename = f"qr_{document_id}.png"
        qr_path = os.path.join(app.config['QR_FOLDER'], qr_filename)
        qr_img.save(qr_path)
        print(f"QR saved to: {qr_path}")

        with open(qr_path, 'rb') as f:
            qr_base64 = base64.b64encode(f.read()).decode('utf-8')
        print(f"QR base64 length: {len(qr_base64)}")

        # Embed QR in document
        file_data = document.get('fileData')
        mime_type = document.get('fileMetadata', {}).get('mimeType', 'application/octet-stream')
        modified_file_data = embed_qr_in_document(file_data, qr_img, mime_type)

        # Update document with QR code and embedded file
        update_data = {
            "qrCode": qr_base64,
            "qrPath": qr_path,
            "verificationUrl": verification_url,
            "qrGeneratedAt": datetime.now()
        }

        if modified_file_data != file_data:
            update_data["fileData"] = modified_file_data
            update_data["originalFileData"] = file_data
            update_data["hasEmbeddedQR"] = True

        result = documents_collection.update_one(
            {"_id": ObjectId(document_id)},
            {"$set": update_data}
        )

        print(f"Database update - matched: {result.matched_count}, modified: {result.modified_count}")

        return jsonify({
            "success": True,
            "message": "QR code generated and embedded in document",
            "qrCode": qr_base64,
            "verificationUrl": verification_url,
            "embedded": modified_file_data != file_data
        }), 200

    except Exception as e:
        print(f"Fix QR error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"message": f"Server error: {str(e)}"}), 500


# ==================== FIX: GENERATE QR FOR ALL VALID DOCUMENTS ====================
@app.route('/api/fix-all-qr', methods=['GET', 'POST'])
def fix_all_qr():
    try:
        # Find all valid documents
        valid_docs = list(documents_collection.find({"status": "valid"}))

        fixed_count = 0
        errors = []
        embedded_count = 0

        for doc in valid_docs:
            try:
                doc_id = str(doc['_id'])

                # Skip if already has QR (optional - remove if you want to regenerate)
                if doc.get('qrCode'):
                    print(f"Document {doc_id} already has QR, skipping")
                    continue

                print(f"Generating QR for document: {doc_id}")

                verification_url = f"{app.config['BASE_URL']}/api/verify-document-qr/{doc_id}"

                qr = qrcode.QRCode(version=1, box_size=10, border=5)
                qr.add_data(verification_url)
                qr.make(fit=True)
                qr_img = qr.make_image(fill_color="black", back_color="white")

                # Ensure QR folder exists
                if not os.path.exists(app.config['QR_FOLDER']):
                    os.makedirs(app.config['QR_FOLDER'])

                qr_filename = f"qr_{doc_id}.png"
                qr_path = os.path.join(app.config['QR_FOLDER'], qr_filename)
                qr_img.save(qr_path)

                with open(qr_path, 'rb') as f:
                    qr_base64 = base64.b64encode(f.read()).decode('utf-8')

                # Embed QR in document
                file_data = doc.get('fileData')
                mime_type = doc.get('fileMetadata', {}).get('mimeType', 'application/octet-stream')
                modified_file_data = embed_qr_in_document(file_data, qr_img, mime_type)

                update_data = {
                    "qrCode": qr_base64,
                    "qrPath": qr_path,
                    "verificationUrl": verification_url,
                    "qrGeneratedAt": datetime.now()
                }

                if modified_file_data != file_data:
                    update_data["fileData"] = modified_file_data
                    update_data["originalFileData"] = file_data
                    update_data["hasEmbeddedQR"] = True
                    embedded_count += 1

                documents_collection.update_one(
                    {"_id": ObjectId(doc_id)},
                    {"$set": update_data}
                )
                fixed_count += 1
                print(f"✅ Generated QR for document: {doc_id}")

            except Exception as e:
                errors.append(f"Document {doc.get('_id')}: {str(e)}")
                print(f"❌ Error for document {doc.get('_id')}: {e}")

        return jsonify({
            "success": True,
            "message": f"QR generation complete",
            "fixed_count": fixed_count,
            "embedded_count": embedded_count,
            "total_valid": len(valid_docs),
            "errors": errors
        }), 200

    except Exception as e:
        print(f"Fix all QR error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"message": f"Server error: {str(e)}"}), 500


if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("🚀 Starting TrustDocs Backend Server")
    print("📡 Port: 5000")
    print("💾 MongoDB: mongodb://127.0.0.1:27017/trustdocs")
    print("📁 Upload folder: ./uploads")
    print("📁 QR folder: ./qrcodes")
    print("=" * 60)
    print("\n📋 PASSWORD MODE: MIXED")
    print("   - Old users: Plain text passwords (will work)")
    print("   - New users: Hashed passwords (SHA-256)")
    print("   - Auto-upgrade: When old users login, they'll be upgraded to hashed")
    print("=" * 60 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)  # This allows connections from other devices