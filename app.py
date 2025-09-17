import streamlit as st
import os
import tempfile
import time
import json
import shutil
from datetime import datetime, timedelta
from crypto.xchacha import generate_key, encrypt_chunk, FILE_NONCE_SIZE
from utils.hashing import blake3_hash, compute_file_hash

# Helper function for logging events
def log_event(event_type, details):
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "event": event_type,
        "user": st.session_state.username if st.session_state.get('logged_in') else "unknown",
        "details": details
    }
    
    # Load existing logs or create new
    try:
        with open("audit_log.json", "r") as f:
            logs = json.load(f)
    except FileNotFoundError:
        logs = []
    
    # Add new log entry
    logs.append(log_entry)
    
    # Keep only the last 1000 entries
    if len(logs) > 1000:
        logs = logs[-1000:]
    
    # Save logs
    with open("audit_log.json", "w") as f:
        json.dump(logs, f, indent=4)

# Setup
st.set_page_config(page_title="Forensic Data Vault", page_icon="🛡️", layout="wide")
USERS_FILE = "users.json"

# Create directories for persistent storage
os.makedirs("encrypted_files", exist_ok=True)
os.makedirs("metadata", exist_ok=True)

# Load users
try:
    with open(USERS_FILE, "r") as f:
        users_data = json.load(f)["users"]
except FileNotFoundError:
    # Initialize with default users if file doesn't exist
    users_data = {
        "admin": {"password": "admin123", "role": "admin", "full_name": "System Administrator", "badge_id": "ADM-001"},
        "investigator1": {"password": "invest123", "role": "investigator", "full_name": "Detective Jane Smith", "badge_id": "INV-001"},
        "analyst1": {"password": "analyst123", "role": "analyst", "full_name": "Forensic Analyst John Doe", "badge_id": "ANA-001"},
        "auditor1": {"password": "auditor123", "role": "auditor", "full_name": "Compliance Auditor Sarah Lee", "badge_id": "AUD-001"}
    }
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    with open(USERS_FILE, "w") as f:
        json.dump({"users": users_data}, f, indent=4)

# Forensic Role definitions with detailed permissions
FORENSIC_ROLES = {
    "admin": {
        "name": "System Administrator",
        "permissions": ["upload", "view_proofs", "decrypt", "manage_users", "audit_logs", "system_config"],
        "description": "Full system access including user management and system configuration"
    },
    "investigator": {
        "name": "Forensic Investigator",
        "permissions": ["upload", "view_proofs", "request_decrypt", "case_management"],
        "description": "Can collect evidence, manage cases, and request decryption access"
    },
    "analyst": {
        "name": "Forensic Analyst",
        "permissions": ["view_proofs", "analyze_evidence", "generate_reports"],
        "description": "Can analyze evidence and generate forensic reports"
    },
    "auditor": {
        "name": "Compliance Auditor",
        "permissions": ["audit_logs", "view_proofs", "verify_chain_of_custody"],
        "description": "Can audit system activities and verify chain of custody"
    },
    "viewer": {
        "name": "Evidence Viewer",
        "permissions": ["view_proofs"],
        "description": "Read-only access to view evidence proofs"
    }
}

# Login/Register
st.title("🛡️ Forensic Data Vault - Secure Login")

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.failed_attempts = 0
    st.session_state.locked_until = None

if not st.session_state.logged_in:
    # Check if account is temporarily locked
    if st.session_state.locked_until and datetime.now() < st.session_state.locked_until:
        remaining_time = (st.session_state.locked_until - datetime.now()).seconds // 60
        st.error(f"Account temporarily locked due to multiple failed attempts. Please try again in {remaining_time} minutes.")
    else:
        st.session_state.locked_until = None
        st.session_state.failed_attempts = 0
        
        choice = st.radio("Select option", ["Login", "Register"])
        username = st.text_input("Username").strip()
        password = st.text_input("Password", type="password")
        
        if choice == "Register":
            st.info("🔒 Registration requires administrative approval for forensic roles")
            full_name = st.text_input("Full Name")
            badge_id = st.text_input("Badge/Employee ID")
            email = st.text_input("Email Address")
            department = st.text_input("Department/Unit")
            
            # Only allow viewer role for self-registration
            role = "viewer"
            st.write(f"**Default Role:** {FORENSIC_ROLES[role]['name']} - {FORENSIC_ROLES[role]['description']}")
            
            if st.button("Request Account"):
                if not all([username, password, full_name, badge_id, email, department]):
                    st.error("All fields are required!")
                elif username in users_data:
                    st.error("Username already exists!")
                else:
                    # Create a pending user request (in a real system, this would go to an admin for approval)
                    users_data[username] = {
                        "password": password, 
                        "role": role,
                        "full_name": full_name,
                        "badge_id": badge_id,
                        "email": email,
                        "department": department,
                        "status": "pending"
                    }
                    with open(USERS_FILE, "w") as f:
                        json.dump({"users": users_data}, f, indent=4)
                    st.success("Account request submitted! Please wait for administrator approval.")

        if choice == "Login":
            if st.button("Login"):
                if username in users_data and users_data[username]["password"] == password:
                    # Check if account is approved
                    if users_data[username].get("status", "active") != "active":
                        st.error("Account pending approval. Please contact administrator.")
                    else:
                        st.session_state.logged_in = True
                        st.session_state.username = username
                        st.session_state.role = users_data[username]["role"]
                        st.session_state.user_info = users_data[username]
                        st.session_state.failed_attempts = 0
                        st.success(f"Access granted! Welcome {st.session_state.user_info.get('full_name', username)}")
                        # Log login event
                        log_event("login_success", f"User {username} logged in successfully")
                else:
                    st.session_state.failed_attempts += 1
                    # Log failed attempt
                    log_event("login_failed", f"Failed login attempt for username: {username}")
                    
                    if st.session_state.failed_attempts >= 3:
                        # Lock account for 15 minutes after 3 failed attempts
                        st.session_state.locked_until = datetime.now() + timedelta(minutes=15)
                        st.error("Too many failed attempts. Account temporarily locked for 15 minutes.")
                    else:
                        st.error(f"Invalid credentials! Attempt {st.session_state.failed_attempts} of 3")

else:
    # User is logged in
    user_role = st.session_state.role
    user_permissions = FORENSIC_ROLES[user_role]["permissions"]
    
    # Display user info in sidebar
    st.sidebar.write(f"### 🔐 Authenticated as:")
    st.sidebar.write(f"**Name:** {st.session_state.user_info.get('full_name', st.session_state.username)}")
    st.sidebar.write(f"**Role:** {FORENSIC_ROLES[user_role]['name']}")
    st.sidebar.write(f"**Badge ID:** {st.session_state.user_info.get('badge_id', 'N/A')}")
    
    if st.sidebar.button("Logout"):
        log_event("logout", f"User {st.session_state.username} logged out")
        st.session_state.logged_in = False
        st.experimental_rerun()
    
    st.title("🛡️ Forensic Data Vault")
    st.markdown(f"Welcome, **{st.session_state.user_info.get('full_name', st.session_state.username)}**")
    st.markdown(f"*Role: {FORENSIC_ROLES[user_role]['name']}*")
    st.markdown("Upload and encrypt forensic evidence securely or view proofs based on your role.")

    # Admin functions
    if "manage_users" in user_permissions:
        with st.sidebar.expander("👥 User Management", expanded=False):
            st.subheader("User Management")
            pending_users = {un: data for un, data in users_data.items() if data.get("status") == "pending"}
            
            if pending_users:
                st.write("**Pending Approvals:**")
                for username, user_data in pending_users.items():
                    with st.expander(f"{user_data.get('full_name', username)}"):
                        st.write(f"Username: {username}")
                        st.write(f"Full Name: {user_data.get('full_name', 'N/A')}")
                        st.write(f"Badge ID: {user_data.get('badge_id', 'N/A')}")
                        st.write(f"Department: {user_data.get('department', 'N/A')}")
                        st.write(f"Email: {user_data.get('email', 'N/A')}")
                        
                        new_role = st.selectbox(
                            "Assign Role",
                            list(FORENSIC_ROLES.keys()),
                            index=list(FORENSIC_ROLES.keys()).index(user_data.get("role", "viewer")),
                            key=f"role_{username}"
                        )
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            if st.button("Approve", key=f"approve_{username}"):
                                users_data[username]["role"] = new_role
                                users_data[username]["status"] = "active"
                                with open(USERS_FILE, "w") as f:
                                    json.dump({"users": users_data}, f, indent=4)
                                log_event("user_approved", f"User {username} approved with role {new_role}")
                                st.success(f"Approved {username} as {new_role}")
                                st.experimental_rerun()
                        with col2:
                            if st.button("Reject", key=f"reject_{username}"):
                                del users_data[username]
                                with open(USERS_FILE, "w") as f:
                                    json.dump({"users": users_data}, f, indent=4)
                                log_event("user_rejected", f"User {username} registration rejected")
                                st.success(f"Rejected {username}")
                                st.experimental_rerun()
            else:
                st.info("No pending user approvals")
            
            # Active users list
            st.write("**Active Users:**")
            for username, user_data in users_data.items():
                if user_data.get("status", "active") == "active" and username != st.session_state.username:
                    st.write(f"- {user_data.get('full_name', username)} ({user_data['role']})")

    # Upload section - only for roles with upload permission
    if "upload" in user_permissions:
        with st.expander("📂 Upload Forensic Evidence File", expanded=True):
            uploaded_file = st.file_uploader("Select file to encrypt", type=None, help="Choose any file format.")

        if uploaded_file:
            with tempfile.NamedTemporaryFile(delete=False) as tfile:
                tfile.write(uploaded_file.getvalue())
                file_path = tfile.name

            file_size = os.path.getsize(file_path)
            st.success(f"✅ File uploaded: **{uploaded_file.name}** ({file_size / (1024*1024):.2f} MB)")

            with st.expander("⚙️ Encryption Settings", expanded=True):
                chunk_size_mb = st.slider("Chunk Size (MB)", min_value=1, max_value=16, value=4)
                chunk_size = chunk_size_mb * 1024 * 1024
                case_id = st.text_input("Case ID", value="CASE-0001")
                evidence_type = st.selectbox("Evidence Type", 
                                           ["Digital Media", "Document", "Image", "Video", "Audio", "Other"])
                description = st.text_area("Evidence Description")
                timestamp = datetime.now().isoformat()

            if st.button("🔒 Encrypt & Generate Proofs"):
                # Log the upload event
                log_event("evidence_upload", 
                         f"User {st.session_state.username} uploaded evidence: {uploaded_file.name} for case {case_id}")
                
                st.info("Encrypting file and generating proofs...")
                key = generate_key()
                file_nonce = os.urandom(FILE_NONCE_SIZE)

                # Create a unique identifier for this file
                file_id = f"{case_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                
                st.subheader("🔑 Encryption Metadata")
                st.json({
                    "key": key.hex(),
                    "file_nonce": file_nonce.hex(),
                    "case_id": case_id,
                    "timestamp": timestamp,
                    "file_id": file_id
                })

                chunk_hashes = []
                total_chunks = 0
                progress = st.progress(0)
                chunk_status = st.empty()

                # Create encrypted file
                encrypted_file_path = os.path.join("encrypted_files", f"{file_id}.enc")
                with open(encrypted_file_path, "wb") as enc_file:
                    with open(file_path, "rb") as f:
                        counter = 0
                        while chunk := f.read(chunk_size):
                            aad_data = json.dumps({
                                "case_id": case_id,
                                "timestamp": timestamp,
                                "chunk_index": counter
                            }).encode()
                            ct = encrypt_chunk(key, file_nonce, counter, chunk, aad_data)
                            ch_hash = blake3_hash(ct)
                            chunk_hashes.append({"chunk": counter, "hash": ch_hash})
                            total_chunks += 1

                            # Write encrypted chunk to file
                            enc_file.write(ct)
                            
                            chunk_status.markdown(f"""
                            **Processing chunk {counter+1}**  
                            Size: {len(chunk)} bytes  
                            Hash: {ch_hash}
                            """)
                            counter += 1
                            progress.progress(min(100, int((f.tell() / file_size) * 100)))
                            time.sleep(0.1)

                file_hash = compute_file_hash(file_path, chunk_size)
                
                # Save metadata
                metadata = {
                    "file_id": file_id,
                    "original_filename": uploaded_file.name,
                    "case_id": case_id,
                    "evidence_type": evidence_type,
                    "description": description,
                    "timestamp": timestamp,
                    "file_size": file_size,
                    "chunk_size": chunk_size,
                    "total_chunks": total_chunks,
                    "file_hash": file_hash,
                    "chunk_hashes": chunk_hashes,
                    "encryption_key": key.hex(),
                    "file_nonce": file_nonce.hex(),
                    "uploaded_by": st.session_state.username,
                    "uploaded_by_name": st.session_state.user_info.get('full_name', st.session_state.username),
                    "uploaded_at": datetime.now().isoformat(),
                    "chain_of_custody": [
                        {
                            "action": "upload",
                            "by": st.session_state.username,
                            "by_name": st.session_state.user_info.get('full_name', st.session_state.username),
                            "timestamp": datetime.now().isoformat(),
                            "role": st.session_state.role
                        }
                    ]
                }
                
                metadata_path = os.path.join("metadata", f"{file_id}.json")
                with open(metadata_path, "w") as mf:
                    json.dump(metadata, mf, indent=4)
                
                st.success("✅ Encryption and hashing completed!")
                st.subheader("📄 File Summary")
                st.write(f"File ID: {file_id}")
                st.write(f"Total chunks processed: **{total_chunks}**")
                st.write(f"File hash (BLAKE3): {file_hash}")
                st.write(f"Encrypted file saved: {encrypted_file_path}")
                st.write(f"Metadata saved: {metadata_path}")

                with st.expander("📂 View All Chunk Hashes", expanded=False):
                    for ch in chunk_hashes:
                        st.text(f"Chunk {ch['chunk']:03d}: {ch['hash']}")

                os.unlink(file_path)
                st.info("Temporary files cleaned up.")

    # View proofs section - available to all roles except those explicitly denied
    if "view_proofs" in user_permissions:
        st.subheader("📂 View Proofs (Read-Only)")
        
        # List all available proofs
        metadata_files = [f for f in os.listdir("metadata") if f.endswith(".json")]
        
        if not metadata_files:
            st.info("No proofs available yet.")
        else:
            st.info(f"Found {len(metadata_files)} proof(s).")
            
            # Filter options based on role
            if "case_management" in user_permissions:
                case_filter = st.text_input("Filter by Case ID")
            else:
                case_filter = ""
            
            for metadata_file in metadata_files:
                with open(os.path.join("metadata", metadata_file), "r") as f:
                    metadata = json.load(f)
                
                # Apply filters based on role permissions
                if case_filter and case_filter.lower() not in metadata['case_id'].lower():
                    continue
                
                with st.expander(f"Proof: {metadata['file_id']} - {metadata['original_filename']}"):
                    st.write(f"**Case ID:** {metadata['case_id']}")
                    st.write(f"**Evidence Type:** {metadata.get('evidence_type', 'N/A')}")
                    st.write(f"**Description:** {metadata.get('description', 'N/A')}")
                    st.write(f"**Uploaded by:** {metadata['uploaded_by_name']} ({metadata['uploaded_by']})")
                    st.write(f"**Uploaded at:** {metadata['uploaded_at']}")
                    st.write(f"**File size:** {metadata['file_size']} bytes")
                    st.write(f"**File hash:** {metadata['file_hash']}")
                    st.write(f"**Total chunks:** {metadata['total_chunks']}")
                    
                    # Show chain of custody for auditors and admins
                    if "verify_chain_of_custody" in user_permissions and "chain_of_custody" in metadata:
                        st.write("**Chain of Custody:**")
                        for event in metadata["chain_of_custody"]:
                            st.write(f"- {event['action']} by {event['by_name']} ({event['role']}) at {event['timestamp']}")
                    
                    if st.checkbox(f"Show chunk hashes for {metadata['file_id']}", key=metadata['file_id']):
                        for ch in metadata['chunk_hashes']:
                            st.text(f"Chunk {ch['chunk']:03d}: {ch['hash']}")

    # Decrypt section - only for roles with decrypt permission
    if "decrypt" in user_permissions:
        st.subheader("🔑 Decrypt Section")
        
        # List encrypted files
        encrypted_files = [f for f in os.listdir("encrypted_files") if f.endswith(".enc")]
        
        if not encrypted_files:
            st.info("No encrypted files available yet.")
        else:
            selected_file = st.selectbox("Select file to decrypt", encrypted_files)
            
            if selected_file:
                file_id = selected_file.replace(".enc", "")
                metadata_path = os.path.join("metadata", f"{file_id}.json")
                
                if os.path.exists(metadata_path):
                    with open(metadata_path, "r") as f:
                        metadata = json.load(f)
                    
                    st.write(f"**Original filename:** {metadata['original_filename']}")
                    st.write(f"**Case ID:** {metadata['case_id']}")
                    st.write(f"**Uploaded by:** {metadata['uploaded_by_name']}")
                    
                    key_hex = st.text_input("Encryption Key (hex)", value=metadata['encryption_key'])
                    nonce_hex = st.text_input("File Nonce (hex)", value=metadata['file_nonce'])
                    
                    if st.button("Decrypt File"):
                        # Log the decryption event
                        log_event("decrypt_attempt", 
                                 f"User {st.session_state.username} attempted to decrypt file: {selected_file}")
                        
                        st.info("Decryption functionality would be implemented here")
                        st.write("This would use the crypto.xchacha.decrypt_chunk function")
                        st.write(f"Key: {key_hex}")
                        st.write(f"Nonce: {nonce_hex}")
                        
                        # Update chain of custody
                        metadata["chain_of_custody"].append({
                            "action": "decrypt_attempt",
                            "by": st.session_state.username,
                            "by_name": st.session_state.user_info.get('full_name', st.session_state.username),
                            "timestamp": datetime.now().isoformat(),
                            "role": st.session_state.role
                        })
                        
                        with open(metadata_path, "w") as f:
                            json.dump(metadata, f, indent=4)
                else:
                    st.error("Metadata not found for this file")

    # Audit logs section - for auditors and admins
    if "audit_logs" in user_permissions:
        with st.expander("📊 Audit Logs", expanded=False):
            st.subheader("System Audit Logs")
            try:
                with open("audit_log.json", "r") as f:
                    logs = json.load(f)
                
                # Display recent logs
                for log in sorted(logs, key=lambda x: x['timestamp'], reverse=True)[:20]:
                    st.write(f"{log['timestamp']} - {log['event']} - {log.get('details', '')}")
            except FileNotFoundError:
                st.info("No audit logs available yet.")