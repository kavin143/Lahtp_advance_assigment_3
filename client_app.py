# client_app.py
import os
import json
import base64
import socket
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from conn_db import Database

# server settings
SERVER_HOST = "localhost"
SERVER_PORT = 8897

# load server-shared key for transport-level encryption to server
with open("secret.key", "rb") as f:
    KEY = f.read()
FERNET = Fernet(KEY)

# DB instance (for register/login)
db = Database()


# --- THIS FUCNTON FOR GENRATE THE PRIVATE AND PUBLIC KEY FOR THE EACH AND EVERY USER ---
def generate_or_load_rsa_keys(username: str):

    # WE GENERATE THE .PEM FILE FOR EVERY USER IT WANT TO STORE IN SAFE WAY 
    # PUBLIC KEY FOR ENCRYPTION 
    # PRIVATE KEY FOR DECRYPTION
    priv_file = f"rsa_priv_{username}.pem"
    pub_file = f"rsa_pub_{username}.pem"

    if os.path.exists(priv_file) and os.path.exists(pub_file):

        with open(priv_file, "rb") as f:
            priv_pem = f.read()
        private_key = serialization.load_pem_private_key(priv_pem, password=None)

        with open(pub_file, "rb") as f:
            pub_pem = f.read()
        return private_key, pub_pem

    # TO GENRATE PRIVATE KEY .PEM
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # TO GENRATE PUBLIC KEY .PEM
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # TO WRITE IN PRIVATE AND PUBLIC FILE
    with open(priv_file, "wb") as f:
        f.write(priv_pem)
        try:
            os.chmod(priv_file, 0o600)
        except Exception:
            pass

    with open(pub_file, "wb") as f:
        f.write(pub_pem)
    return private_key, pub_pem

# THIS FUNCTION FOR ENCRYPT THE RSA WITH BASE64
def rsa_encrypt_with_pub_pem_b64(pub_pem_b64: str, plaintext: bytes) -> str:

    pub_pem = base64.b64decode(pub_pem_b64)

    pubkey = serialization.load_pem_public_key(pub_pem)
    ct = pubkey.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    return base64.b64encode(ct).decode()

# THIS FUNCTION FOR DECRYPT THE RSA PRIVATE KEY WITH BASE64
def rsa_decrypt_with_priv(private_key, ct_b64: str) -> bytes:

    ct = base64.b64decode(ct_b64)
    pt = private_key.decrypt(
        ct,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    return pt


# GRAPHICAL USER INTERFACE FOR OUR CHAT APPLICTION
# WE USE THE TKINTER FOR GUI

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Chat — Login/Register")
        self.geometry("900x520")
        self.resizable(False, False)

        # networking & crypto
        self.sock = None
        self.listener_thread = None

        # user state
        self.username = None
        self.private_key = None
        self.pub_pem = None  # bytes
        self.pub_pem_b64 = None  # str

        # E2E state
        self.pubkey_cache = {}      # username -> pubkey_b64
        self.peer_session = {}      # username -> Fernet instance
        self.pending_e2e_target = None
        self.current_target = None  # currently active private recipient (or None)

        # UI
        self.build_ui()

    def build_ui(self):
        container = tk.Frame(self, bg="#f0e5f7")
        container.pack(fill="both", expand=True)

        left = tk.Frame(container, width=300, bg="#3b1743")
        left.pack(side="left", fill="y")
        left.pack_propagate(False)

        right = tk.Frame(container, bg="#f4eaf6")
        right.pack(side="right", fill="both", expand=True)

        tk.Label(left, text="Chat Application", fg="white",
                 bg="#3b1743", font=("Helvetica", 14, "bold"), pady=20).pack()

        tk.Button(left, text="Login", width=18, command=self.show_login, bg="#c49bd9").pack(pady=10)
        tk.Button(left, text="Register", width=18, command=self.show_register, bg="#c49bd9").pack(pady=5)

        self.right_container = right
        self.show_login()

    def clear_right(self):
        for w in self.right_container.winfo_children():
            w.destroy()

    def show_login(self):
        self.clear_right()
        frame = tk.Frame(self.right_container, bg="#f4eaf6", padx=20, pady=20)
        frame.pack(fill="both", expand=True)
        tk.Label(frame, text="Login", font=("Helvetica", 18, "bold"), bg="#f4eaf6").pack(pady=10)

        tk.Label(frame, text="Username:", bg="#f4eaf6").pack(anchor="w")
        self.login_user = tk.Entry(frame, width=40)
        self.login_user.pack(pady=5)

        tk.Label(frame, text="Password:", bg="#f4eaf6").pack(anchor="w")
        self.login_pass = tk.Entry(frame, width=40, show="*")
        self.login_pass.pack(pady=5)

        tk.Button(frame, text="Login", bg="#6b2b6b", fg="white", width=20, command=self.do_login).pack(pady=10)
        tk.Button(frame, text="Go to Register", command=self.show_register).pack()

        # allow Enter to submit
        self.login_pass.bind("<Return>", lambda e: self.do_login())

    def show_register(self):
        self.clear_right()
        frame = tk.Frame(self.right_container, bg="#f4eaf6", padx=20, pady=20)
        frame.pack(fill="both", expand=True)
        tk.Label(frame, text="Register", font=("Helvetica", 18, "bold"), bg="#f4eaf6").pack(pady=10)

        tk.Label(frame, text="Username:", bg="#f4eaf6").pack(anchor="w")
        self.reg_user = tk.Entry(frame, width=40)
        self.reg_user.pack(pady=5)

        tk.Label(frame, text="Password:", bg="#f4eaf6").pack(anchor="w")
        self.reg_pass = tk.Entry(frame, width=40, show="*")
        self.reg_pass.pack(pady=5)

        tk.Button(frame, text="Register", bg="#6b2b6b", fg="white", width=20, command=self.do_register).pack(pady=10)
        tk.Button(frame, text="Go to Login", command=self.show_login).pack()

        self.reg_pass.bind("<Return>", lambda e: self.do_register())

    def do_register(self):
        username = self.reg_user.get().strip()
        password = self.reg_pass.get()
        ok, msg = db.create_user(username, password)
        if ok:
            messagebox.showinfo("Success", "Registered successfully. Now login.")
            self.show_login()
        else:
            messagebox.showerror("Error", msg)

    def do_login(self):
        username = self.login_user.get().strip()
        password = self.login_pass.get()
        ok, msg = db.verify_user(username, password)
        if ok:
            self.username = username
            messagebox.showinfo("Welcome", f"Welcome {username} — opening chat")
            self.open_chat()
        else:
            messagebox.showerror("Login failed", msg)

    # ---- Chat UI & socket ----
    def open_chat(self):
        self.clear_right()
        self.title(f"Secure Chat — {self.username}")

        # prepare RSA keys for this user
        self.private_key, self.pub_pem = generate_or_load_rsa_keys(self.username)
        self.pub_pem_b64 = base64.b64encode(self.pub_pem).decode()

        frame = tk.Frame(self.right_container, bg="#f4eaf6", padx=10, pady=10)
        frame.pack(fill="both", expand=True)

        top_frame = tk.Frame(frame, bg="#f4eaf6")
        top_frame.pack(fill="x")
        tk.Label(top_frame, text=f"Logged in as: {self.username}", bg="#f4eaf6", font=("Helvetica", 10, "bold")).pack(side="left")

        btn_logout = tk.Button(top_frame, text="Logout", command=self.logout)
        btn_logout.pack(side="right")

        # Middle: chat area + online users
        middle = tk.Frame(frame, bg="#f4eaf6")
        middle.pack(fill="both", expand=True)

        left_area = tk.Frame(middle, bg="#f4eaf6")
        left_area.pack(side="left", fill="both", expand=True)

        right_area = tk.Frame(middle, width=220, bg="#f4eaf6")
        right_area.pack(side="right", fill="y")
        right_area.pack_propagate(False)

        # message area (left)
        self.txt_area = scrolledtext.ScrolledText(left_area, state="disabled", width=60, height=20, wrap="word", font=("Helvetica", 10))
        self.txt_area.pack(pady=10, fill="both", expand=True)

        # entry + send (left bottom)
        bottom = tk.Frame(left_area, bg="#f4eaf6")
        bottom.pack(fill="x")
        self.msg_entry = tk.Entry(bottom, width=60)
        self.msg_entry.pack(side="left", padx=(0,8), pady=5)
        self.msg_entry.bind("<Return>", lambda e: self.send_message())

        tk.Button(bottom, text="Send", width=12, command=self.send_message, bg="#6b2b6b", fg="white").pack(side="left")

        # connect to server and announce
        self.connect_to_server()
        # first announce join (plaintext) then announce pubkey as JSON envelope
        self.send_raw(f"**JOIN**::{self.username}")
        # send pubkey announcement
        self.send_json({"type": "pubkey", "username": self.username, "pubkey": self.pub_pem_b64})

    def append_text(self, text: str):
        self.txt_area.configure(state="normal")
        self.txt_area.insert("end", text + "\n")
        self.txt_area.configure(state="disabled")
        self.txt_area.see("end")

    def connect_to_server(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((SERVER_HOST, SERVER_PORT))
        except Exception as e:
            messagebox.showerror("Connection error", f"Cannot connect to server: {e}")
            return

        # start listener thread
        self.listener_thread = threading.Thread(target=self.listen_for_messages, daemon=True)
        self.listener_thread.start()
        self.append_text("Connected to server.")

    # envelope helpers
    def send_json(self, obj: dict):
        if not self.sock:
            messagebox.showerror("Not connected", "Socket not connected")
            return
        raw = json.dumps(obj).encode()
        enc = FERNET.encrypt(raw)
        try:
            self.sock.sendall(enc)
        except Exception as e:
            messagebox.showerror("Send failed", str(e))

    def send_raw(self, text: str):
        if not self.sock:
            messagebox.showerror("Not connected", "Socket not connected")
            return
        enc = FERNET.encrypt(text.encode())
        try:
            self.sock.sendall(enc)
        except Exception as e:
            messagebox.showerror("Send failed", str(e))

# THE FUCNTION FOR LESTION THE MESSAGE FORM THE USER AND DISPLAY
    def listen_for_messages(self):
        try:
            while True:
                data = self.sock.recv(8192)
                if not data:
                    break
                try:
                    decrypted = FERNET.decrypt(data).decode()
                except Exception:
                    # ignore malformed data
                    continue

                # try JSON control message first
                try:
                    obj = json.loads(decrypted)
                except Exception:
                    obj = None

                if obj:
                    t = obj.get("type")
                    if t == "user_list":
                        users = obj.get("users", [])
                        self.update_user_listbox(users)

                    elif t == "pubkey":
                        # store the announced public key silently (do NOT print the large base64)
                        uname = obj.get("username")
                        pub = obj.get("pubkey")
                        if uname and pub:
                            self.pubkey_cache[uname] = pub
                            # silently update UI or notify short message
                            # self.append_text(f"[SYSTEM] Received public key announcement for {uname}")

                    elif t == "pubkey_response":
                        # server response to a get_pubkey request
                        uname = obj.get("username")
                        pub = obj.get("pubkey")
                        if uname and pub:
                            self.pubkey_cache[uname] = pub
                            self.append_text(f"[SYSTEM] Got public key for {uname}")
                            # if waiting to start an E2E with this user, proceed
                            if self.pending_e2e_target == uname:
                                self.pending_e2e_target = None
                                self.start_session_with(uname)

                    elif t == "session_key":
                        # someone sent a session key to us
                        to = obj.get("to")
                        fr = obj.get("from")
                        if to == self.username and fr:
                            enc_key_b64 = obj.get("encrypted_key")
                            try:
                                session_key = rsa_decrypt_with_priv(self.private_key, enc_key_b64)
                                self.peer_session[fr] = Fernet(session_key)
                                self.append_text(f"[SYSTEM] E2E session established with {fr}")
                            except Exception as e:
                                self.append_text(f"[SYSTEM] Failed to decrypt session key from {fr}: {e}")

                    elif t == "e2e_msg":
                        to = obj.get("to")
                        fr = obj.get("from")
                        if to == self.username and fr:
                            payload_b64 = obj.get("payload")
                            if fr not in self.peer_session:
                                self.append_text(f"[SYSTEM] Received private message from {fr} but no session key. Requesting pubkey...")
                                # request pubkey (optionally) - message cannot be decrypted until session key exchanged
                                self.send_json({"type": "get_pubkey", "requester": self.username, "target": fr})
                            else:
                                try:
                                    payload_bytes = base64.b64decode(payload_b64)
                                    plain = self.peer_session[fr].decrypt(payload_bytes).decode()
                                    self.append_text(f"{fr} (private): {plain}")
                                except Exception as e:
                                    self.append_text(f"[SYSTEM] Failed decrypting e2e msg from {fr}: {e}")

                    elif t == "error":
                        self.append_text(f"[SERVER ERROR] {obj.get('message')}")

                    else:
                        # unknown JSON control — do not print the full object to chat; print a short debug line
                        self.append_text(f"[SYSTEM] Received unknown control message type: {t}")

                else:
                    # plaintext system messages & legacy messages
                    if decrypted.startswith("**JOIN**::"):
                        user_joined = decrypted.split("::", 1)[1]
                        self.append_text(f"[SYSTEM] {user_joined} has joined the chat.")

                    elif decrypted.startswith("[JSON]"):  # legacy marker
                        self.append_text("[SYSTEM] Public keys exchanged securely.")

                    else:
                        self.append_text(decrypted)

        except Exception as e:
            self.append_text(f"[Connection closed: {e}]")
        finally:
            try:
                self.sock.close()
            except:
                pass

    # UI actions for E2E
    def update_user_listbox(self, users):
        # keep internal cache updated but do not overwrite pubkey cache
        self.user_listbox.delete(0, "end")
        for u in users:
            self.user_listbox.insert("end", u)

    def on_start_e2e(self):
        sel = self.user_listbox.curselection()
        if not sel:
            messagebox.showinfo("Select user", "Please select a user from the list.")
            return
        target = self.user_listbox.get(sel[0])
        if target == self.username:
            messagebox.showinfo("Invalid", "Cannot start E2E with yourself.")
            return

        # if we already have pubkey cached -> create session key immediately
        if target in self.pubkey_cache:
            self.start_session_with(target)
        else:
            self.append_text(f"[SYSTEM] Requesting public key for {target}...")
            # request pubkey from server; will receive pubkey_response
            self.pending_e2e_target = target
            self.send_json({"type": "get_pubkey", "requester": self.username, "target": target})

    def start_session_with(self, target):
        # create symmetric session key and send RSA-wrapped key to target
        pub_b64 = self.pubkey_cache.get(target)
        if not pub_b64:
            self.append_text(f"[SYSTEM] No public key for {target}.")
            return
        session_key = Fernet.generate_key()
        try:
            enc_key_b64 = rsa_encrypt_with_pub_pem_b64(pub_b64, session_key)
        except Exception as e:
            self.append_text(f"[SYSTEM] RSA encrypt failed: {e}")
            return
        # send session key envelope
        obj = {"type": "session_key", "from": self.username, "to": target, "encrypted_key": enc_key_b64}
        self.send_json(obj)
        # store our local session
        self.peer_session[target] = Fernet(session_key)
        self.current_target = target
        self.target_label.config(text=f"Target: {self.current_target}")
        self.append_text(f"[SYSTEM] Sent session key to {target} — private channel ready.")

    def clear_target(self):
        self.current_target = None
        self.target_label.config(text="Target: None")
        self.append_text("[SYSTEM] Cleared private target — messages will be public.")

    # sending: if current_target set and session exists -> send E2E, else broadcast
    def send_message(self):
        txt = self.msg_entry.get().strip()
        if not txt:
            return

        if self.current_target:
            # private E2E
            target = self.current_target
            if target not in self.peer_session:
                self.append_text("[SYSTEM] No session key for target. Start E2E first.")
            else:
                f = self.peer_session[target]
                ciphertext = f.encrypt(txt.encode())
                payload_b64 = base64.b64encode(ciphertext).decode()
                obj = {"type": "e2e_msg", "from": self.username, "to": target, "payload": payload_b64}
                self.send_json(obj)
                self.append_text(f"You -> {target} (private): {txt}")
        else:
            # public broadcast
            self.append_text(f"You: {txt}")
            self.send_raw(f"{self.username}: {txt}")

        self.msg_entry.delete(0, "end")

    def logout(self):
        try:
            if self.sock:
                self.send_raw(f"**LEFT**::{self.username}")
                self.sock.close()
        except:
            pass
        self.username = None
        self.private_key = None
        self.pub_pem = None
        self.pub_pem_b64 = None
        self.pubkey_cache.clear()
        self.peer_session.clear()
        self.pending_e2e_target = None
        self.current_target = None
        self.title("Secure Chat — Login/Register")
        self.show_login()

    def on_closing(self):
        self.logout()
        db.close()
        self.destroy()


if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
