import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import datetime
import os
import ctypes
import sys

def _set_dpi_awareness():
    if sys.platform == "win32":
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass

_set_dpi_awareness()

from pki.ca import create_ca
from pki.user import create_user_key_and_csr
from pki.certificate import issue_certificate
from pki.validation import validate_certificate
from pki.crl import revoke_certificate
from crypto.hybrid import encrypt_file, decrypt_file
from crypto.signing import sign_file, verify_signature
from attacks.mitm_simulation import simulate_mitm_attack_demo
from attacks.replay_attack import simulate_replay_demo

BG_COLOR       = "#0f0f12"
SIDEBAR_COLOR  = "#16161a"
FRAME_COLOR    = "#1c1c22"
CARD_COLOR     = "#222228"
BORDER_COLOR   = "#2e2e38"
BTN_COLOR      = "#2563eb"
BTN_HOVER      = "#1d4ed8"
BTN_ACTIVE     = "#1e40af"
ACCENT_COLOR   = "#60a5fa"
TEXT_COLOR     = "#e2e8f0"
TEXT_MUTED     = "#94a3b8"
SECTION_COLOR  = "#475569"
LOG_SUCCESS    = "#4ade80"
LOG_ERROR      = "#f87171"
LOG_WARNING    = "#fbbf24"
LOG_INFO       = "#60a5fa"

FONT_TITLE     = ("Segoe UI", 13, "bold")
FONT_SECTION   = ("Segoe UI", 10, "bold")
FONT_BTN       = ("Segoe UI", 10)
FONT_LOG       = ("Cascadia Code", 9) if sys.platform == "win32" else ("Menlo", 10)
FONT_LABEL     = ("Segoe UI", 10)

def log_event(log_widget, msg, color=LOG_SUCCESS):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    log_widget.configure(state="normal")
    log_widget.insert(tk.END, f"[{timestamp}] ", LOG_INFO)
    log_widget.insert(tk.END, f"{msg}\n", color)
    log_widget.see(tk.END)
    log_widget.configure(state="disabled")

def handle_errors(log_widget):
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                log_event(log_widget, f"Error: {e}", LOG_ERROR)
        return wrapper
    return decorator

def ask_string_top(root, title, prompt, show=None):
    result = {"value": None}
    dialog = tk.Toplevel(root)
    dialog.title(title)
    dialog.configure(bg=FRAME_COLOR)
    dialog.resizable(False, False)
    dialog.transient(root)
    dialog.grab_set()

    header = tk.Frame(dialog, bg=BTN_COLOR, height=4)
    header.pack(fill="x")

    tk.Label(dialog, text=prompt, bg=FRAME_COLOR, fg=TEXT_COLOR,
             font=FONT_LABEL).pack(padx=24, pady=(18, 6), anchor="w")

    entry_frame = tk.Frame(dialog, bg=BORDER_COLOR, pady=1)
    entry_frame.pack(padx=24, pady=(0, 18), fill="x")
    entry = tk.Entry(entry_frame, show=show, font=FONT_LOG,
                     bg=CARD_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR,
                     relief="flat", bd=8)
    entry.pack(fill="x")
    entry.focus_set()

    def on_ok():
        result["value"] = entry.get()
        dialog.destroy()

    def on_cancel():
        dialog.destroy()

    btn_frame = tk.Frame(dialog, bg=FRAME_COLOR)
    btn_frame.pack(pady=(0, 18), padx=24, anchor="e")

    for text, cmd in [("Cancel", on_cancel), ("  OK  ", on_ok)]:
        b = tk.Button(btn_frame, text=text, command=cmd, font=FONT_BTN,
                      bg=BTN_COLOR if text.strip() == "OK" else CARD_COLOR,
                      fg=TEXT_COLOR, activebackground=BTN_HOVER,
                      activeforeground=TEXT_COLOR, relief="flat", bd=0,
                      padx=14, pady=6, cursor="hand2")
        b.pack(side="right", padx=(6, 0))

    dialog.bind("<Return>", lambda e: on_ok())
    dialog.bind("<Escape>", lambda e: on_cancel())
    dialog.update_idletasks()
    w, h = dialog.winfo_width(), dialog.winfo_height()
    ws, hs = dialog.winfo_screenwidth(), dialog.winfo_screenheight()
    dialog.geometry(f"{max(w,320)}x{h}+{(ws-max(w,320))//2}+{(hs-h)//2}")
    root.wait_window(dialog)
    return result["value"]

def ask_user_credentials(root, action="Enter"):
    name = ask_string_top(root, action, "Username:")
    if not name:
        return None, None
    password = ask_string_top(root, action, "Password:", show="*")
    return name, password

def sidebar_button(parent, text, command, icon=""):
    full_text = f"  {icon}  {text}" if icon else f"  {text}"
    btn = tk.Button(
        parent, text=full_text, command=command,
        bg=SIDEBAR_COLOR, fg=TEXT_MUTED,
        activebackground=CARD_COLOR, activeforeground=TEXT_COLOR,
        relief="flat", font=FONT_BTN,
        anchor="w", padx=4, pady=9,
        borderwidth=0, cursor="hand2",
    )

    def on_enter(e):
        btn.config(bg=CARD_COLOR, fg=TEXT_COLOR)

    def on_leave(e):
        btn.config(bg=SIDEBAR_COLOR, fg=TEXT_MUTED)

    btn.bind("<Enter>", on_enter)
    btn.bind("<Leave>", on_leave)
    return btn

def section_label(parent, text):
    frame = tk.Frame(parent, bg=SIDEBAR_COLOR)
    frame.pack(fill="x", padx=12, pady=(18, 4))
    tk.Frame(frame, bg=BORDER_COLOR, height=1).pack(fill="x", pady=(0, 6))
    tk.Label(frame, text=text.upper(), bg=SIDEBAR_COLOR, fg=SECTION_COLOR,
             font=FONT_SECTION, anchor="w").pack(fill="x")

def start_gui(ROOT_DIR):
    root = tk.Tk()

    if sys.platform == "win32":
        try:
            scale = ctypes.windll.shcore.GetScaleFactorForDevice(0) / 100
            root.tk.call("tk", "scaling", scale * 96 / 72)
        except Exception:
            root.tk.call("tk", "scaling", root.winfo_fpixels("1i") / 72)

    root.geometry("1260x780")
    root.minsize(900, 600)
    root.title("CryptyPKI  ·  Dashboard")
    root.configure(bg=BG_COLOR)

    sidebar = tk.Frame(root, bg=SIDEBAR_COLOR, width=260)
    sidebar.pack(side="left", fill="y")
    sidebar.pack_propagate(False)

    tk.Frame(root, bg=BORDER_COLOR, width=1).pack(side="left", fill="y")

    content = tk.Frame(root, bg=BG_COLOR)
    content.pack(side="right", fill="both", expand=True)

    header_frame = tk.Frame(sidebar, bg=BTN_COLOR, height=56)
    header_frame.pack(fill="x")
    header_frame.pack_propagate(False)
    tk.Label(header_frame, text="⬡  CryptyPKI", bg=BTN_COLOR, fg="#ffffff",
             font=("Segoe UI", 12, "bold")).pack(expand=True, anchor="w", padx=16)

    log_header = tk.Frame(content, bg=BG_COLOR)
    log_header.pack(fill="x", padx=20, pady=(16, 4))

    tk.Label(log_header, text="Activity Log", bg=BG_COLOR, fg=TEXT_COLOR,
             font=FONT_TITLE).pack(side="left")

    def clear_log():
        log_panel.configure(state="normal")
        log_panel.delete("1.0", tk.END)
        log_panel.configure(state="disabled")

    tk.Button(log_header, text="Clear", command=clear_log,
              bg=CARD_COLOR, fg=TEXT_MUTED, activebackground=BORDER_COLOR,
              activeforeground=TEXT_COLOR, relief="flat", font=FONT_BTN,
              padx=10, pady=4, cursor="hand2").pack(side="right")

    log_border = tk.Frame(content, bg=BORDER_COLOR, bd=0)
    log_border.pack(fill="both", expand=True, padx=20, pady=(0, 20))
    inner = tk.Frame(log_border, bg=CARD_COLOR, bd=1)
    inner.pack(fill="both", expand=True, padx=1, pady=1)

    log_panel = scrolledtext.ScrolledText(
        inner, bg=CARD_COLOR, fg=LOG_SUCCESS,
        font=FONT_LOG, insertbackground=TEXT_COLOR,
        state="disabled", relief="flat", bd=0,
        selectbackground=BTN_COLOR, selectforeground="#ffffff",
        wrap="word",
    )
    log_panel.pack(fill="both", expand=True, padx=2, pady=2)

    log_panel.tag_config(LOG_SUCCESS, foreground=LOG_SUCCESS)
    log_panel.tag_config(LOG_ERROR,   foreground=LOG_ERROR)
    log_panel.tag_config(LOG_WARNING, foreground=LOG_WARNING)
    log_panel.tag_config(LOG_INFO,    foreground=LOG_INFO)

    log_event(log_panel, "CryptyPKI ready.", LOG_INFO)

    section_label(sidebar, "PKI Management")

    def _create_ca():
        create_ca(ROOT_DIR)
        log_event(log_panel, "Root CA created successfully.")

    sidebar_button(sidebar, "Create Root CA", _create_ca, "🔐").pack(
        fill="x", padx=8, pady=1)

    @handle_errors(log_panel)
    def create_user():
        name, password = ask_user_credentials(root, "Create User")
        if not name or not password:
            return
        user_key_path  = os.path.join(ROOT_DIR, "users", f"{name}_key.pem")
        user_cert_path = os.path.join(ROOT_DIR, "users", f"{name}_cert.pem")
        if os.path.exists(user_key_path) or os.path.exists(user_cert_path):
            log_event(log_panel, f"User '{name}' already exists.", LOG_WARNING)
            messagebox.showwarning("Duplicate User", f"User '{name}' already exists!")
            return
        create_user_key_and_csr(name, password, ROOT_DIR)
        issue_certificate(name, ROOT_DIR)
        log_event(log_panel, f"User '{name}' created with certificate.")

    sidebar_button(sidebar, "Create User + Cert", create_user, "👤").pack(
        fill="x", padx=8, pady=1)

    @handle_errors(log_panel)
    def validate_cert():
        name = ask_string_top(root, "Validate Certificate", "Enter username:")
        if name:
            cert_path = os.path.join(ROOT_DIR, "users", f"{name}_cert.pem")
            valid, msg = validate_certificate(cert_path, ROOT_DIR)
            color = LOG_SUCCESS if valid else LOG_ERROR
            log_event(log_panel, f"Validation for '{name}': {msg}", color)
            messagebox.showinfo("Validation Result", msg)

    sidebar_button(sidebar, "Validate Certificate", validate_cert, "✅").pack(
        fill="x", padx=8, pady=1)

    @handle_errors(log_panel)
    def revoke_cert():
        name = ask_string_top(root, "Revoke Certificate", "Enter username:")
        if name:
            revoke_certificate(name, ROOT_DIR)
            log_event(log_panel, f"Certificate revoked for '{name}'.", LOG_WARNING)

    sidebar_button(sidebar, "Revoke Certificate", revoke_cert, "🚫").pack(
        fill="x", padx=8, pady=1)

    section_label(sidebar, "Crypto Operations")

    @handle_errors(log_panel)
    def sign():
        file_path = filedialog.askopenfilename(title="Select file to sign")
        name, password = ask_user_credentials(root, "Sign File")
        if file_path and name and password:
            sign_file(file_path, name, password, ROOT_DIR)
            log_event(log_panel, f"'{name}' signed: {os.path.basename(file_path)}")

    sidebar_button(sidebar, "Sign File", sign, "✍️").pack(fill="x", padx=8, pady=1)

    @handle_errors(log_panel)
    def verify():
        file_path = filedialog.askopenfilename(title="Select file to verify")
        name = ask_string_top(root, "Verify Signature", "Enter username:")
        if file_path and name:
            valid, msg = verify_signature(file_path, name, ROOT_DIR)
            color = LOG_SUCCESS if valid else LOG_ERROR
            log_event(log_panel, f"Verify '{os.path.basename(file_path)}': {msg}", color)
            messagebox.showinfo("Verification Result", msg)

    sidebar_button(sidebar, "Verify Signature", verify, "🔍").pack(
        fill="x", padx=8, pady=1)

    @handle_errors(log_panel)
    def encrypt():
        file_path = filedialog.askopenfilename(title="Select file to encrypt")
        receiver = ask_string_top(root, "Encrypt File", "Receiver username:")
        if file_path and receiver:
            encrypt_file(file_path, receiver, ROOT_DIR)
            log_event(log_panel,
                      f"Encrypted '{os.path.basename(file_path)}' → {receiver}")

    sidebar_button(sidebar, "Encrypt File", encrypt, "🔒").pack(
        fill="x", padx=8, pady=1)

    @handle_errors(log_panel)
    def decrypt():
        file_path = filedialog.askopenfilename(title="Select file to decrypt")
        name, password = ask_user_credentials(root, "Decrypt File")
        if file_path and name and password:
            decrypt_file(file_path, name, password, ROOT_DIR)
            log_event(log_panel,
                      f"'{name}' decrypted: {os.path.basename(file_path)}")

    sidebar_button(sidebar, "Decrypt File", decrypt, "🔓").pack(
        fill="x", padx=8, pady=1)

    section_label(sidebar, "Attack Simulations")

    sidebar_button(
        sidebar, "Simulate MITM Attack",
        lambda: log_event(log_panel, simulate_mitm_attack_demo(ROOT_DIR), LOG_WARNING),
        "⚠️"
    ).pack(fill="x", padx=8, pady=1)

    sidebar_button(
        sidebar, "Simulate Replay Attack",
        lambda: log_event(log_panel, simulate_replay_demo(), LOG_WARNING),
        "🔁"
    ).pack(fill="x", padx=8, pady=1)

    root.mainloop()