import random
from hashlib import sha256
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk, filedialog, PhotoImage
# Add clipboard support
import pyperclip
# ECC support
try:
    from ecdsa import SigningKey, VerifyingKey, NIST192p, NIST224p, NIST256p, NIST384p, NIST521p, BadSignatureError
except ImportError:
    SigningKey = None
    VerifyingKey = None
    NIST192p = NIST224p = NIST256p = NIST384p = NIST521p = None
    BadSignatureError = None

import base64
import os


#! ------------------------------------------------------------------------------------------------------------------------ #
#!                                                        RSA Algorithm                                                     #
#! ------------------------------------------------------------------------------------------------------------------------ #





#* ------------------------------ Coprime Checker ----------------------------- #

def coprime(a, b):                                      #!Check Coprime (if result 1 -> Coprime) For RSA
    while b: a, b = b, a % b
    return a
    

#* -------------------------------- GCD Checker ------------------------------- #

def extended_gcd(aa, bb):
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)





#* ------------------------------ Modular Inverse ----------------------------- #

def modinv(a, m):                                       #! a⁻¹ mod m (Modular Inverse)
    g, x, _ = extended_gcd(a, m)                        #! Get GCD and X
    if g != 1: 
        raise Exception('Modular inverse does not exist')  #! Inverse if GCD(a,m) = 1  
    return x % m    




#* ------------------------------- Prime Checker ------------------------------ #

def is_prime(num):
    if num < 2 or num % 2 == 0: return num == 2
    return all(num % i != 0 for i in range(3, int(num**0.5) + 2, 2))




#* ------------------------------- Key Generation ------------------------------ #

def generate_keypair(p, q):                             #!  P  q
    if not (is_prime(p) and is_prime(q)) or p == q:     #! Check if both are prime and different
        raise ValueError('Both numbers must be different primes')      
    n, phi = p * q, (p-1) * (q-1)                       #! n = p * q,  φ(n) = (p-1) * (q-1)
    e = random.randrange(1, phi)                        #! 1 < e < φ(n)
    while coprime(e, phi) != 1:                         #! Ensure e is coprime to φ(n)
        e = random.randrange(1, phi)
    d = modinv(e, phi)                                  #! d = e⁻¹ mod φ(n)                    
    return ((e, n), (d, n))                             #! Public key, Private key



#* ------------------------------- Encryption/Decryption ------------------------------ #

def encrypt(key, plaintext):
    e, n = key
    return [pow(ord(char), e, n) for char in plaintext] #! C = Mᵉ mod n

def decrypt(key, ciphertext):
    d, n = key
    return ''.join(chr(pow(char, d, n)) for char in ciphertext) #! M = Cᵈ mod n



#* ------------------------------- Hash Function ------------------------------ #   
#  
def hashFunction(message):
    return sha256(message.encode("UTF-8")).hexdigest()          #! SHA-256 Hashing







class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tipwindow = None
        widget.bind("<Enter>", self.show_tip)
        widget.bind("<Leave>", self.hide_tip)

    def show_tip(self, event=None):
        if self.tipwindow or not self.text: return
        x = self.widget.winfo_rootx() + 25
        y = self.widget.winfo_rooty() + 20
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        tk.Label(tw, text=self.text, justify=tk.LEFT, background="#ffffe0", 
                relief=tk.SOLID, borderwidth=1, font=("tahoma", "8", "normal")).pack(ipadx=1)

    def hide_tip(self, event=None):
        if self.tipwindow:
            self.tipwindow.destroy()
            self.tipwindow = None

class CryptoGUI:
    def __init__(self, master):
        self.master = master
        master.title("Crypto GUI (RSA & ECC)")
        master.geometry("900x800")

        # Theme definitions
        self.themes = {
            "Light": {
                "accent": "#2563eb",
                "bg": "#f6f8fa",
                "card_bg": "#ffffff",
                "card_border": "#e5e7eb",
                "button_bg": "#2563eb",
                "button_fg": "#ffffff",
                "button_hover": "#1e40af",
                "text": "#222222",
                "output_bg": "#222831",
                "output_fg": "#eeeeee",
                "status_success": "#d1fae5",
                "status_warning": "#fef9c3",
                "status_error": "#fee2e2",
                "status_info": "#e5e7eb",
                "text_button_bg": "#f3f4f6",
                "text_button_fg": "#374151",
                "text_button_hover": "#e5e7eb"
            },
            "Dark": {
                "accent": "#3b82f6",
                "bg": "#111827",
                "card_bg": "#1f2937",
                "card_border": "#374151",
                "button_bg": "#3b82f6",
                "button_fg": "#ffffff",
                "button_hover": "#2563eb",
                "text": "#f3f4f6",
                "output_bg": "#000000",
                "output_fg": "#00ff00",
                "status_success": "#064e3b",
                "status_warning": "#78350f",
                "status_error": "#7f1d1d",
                "status_info": "#1f2937",
                "text_button_bg": "#374151",
                "text_button_fg": "#f3f4f6",
                "text_button_hover": "#4b5563"
            },
            "Ocean": {
                "accent": "#0891b2",
                "bg": "#e0f2fe",
                "card_bg": "#ffffff",
                "card_border": "#bae6fd",
                "button_bg": "#0891b2",
                "button_fg": "#ffffff",
                "button_hover": "#0e7490",
                "text": "#164e63",
                "output_bg": "#164e63",
                "output_fg": "#e0f2fe",
                "status_success": "#ecfdf5",
                "status_warning": "#fffbeb",
                "status_error": "#fef2f2",
                "status_info": "#f0f9ff",
                "text_button_bg": "#e0f2fe",
                "text_button_fg": "#164e63",
                "text_button_hover": "#bae6fd"
            },
            "Forest": {
                "accent": "#16a34a",
                "bg": "#f0fdf4",
                "card_bg": "#ffffff",
                "card_border": "#dcfce7",
                "button_bg": "#16a34a",
                "button_fg": "#ffffff",
                "button_hover": "#15803d",
                "text": "#166534",
                "output_bg": "#166534",
                "output_fg": "#f0fdf4",
                "status_success": "#ecfdf5",
                "status_warning": "#fffbeb",
                "status_error": "#fef2f2",
                "status_info": "#f0fdf4",
                "text_button_bg": "#dcfce7",
                "text_button_fg": "#166534",
                "text_button_hover": "#bbf7d0"
            },
            "Sunset": {
                "accent": "#f97316",
                "bg": "#fff7ed",
                "card_bg": "#ffffff",
                "card_border": "#ffedd5",
                "button_bg": "#f97316",
                "button_fg": "#ffffff",
                "button_hover": "#ea580c",
                "text": "#7c2d12",
                "output_bg": "#7c2d12",
                "output_fg": "#fff7ed",
                "status_success": "#ecfdf5",
                "status_warning": "#fffbeb",
                "status_error": "#fef2f2",
                "status_info": "#fff7ed",
                "text_button_bg": "#ffedd5",
                "text_button_fg": "#7c2d12",
                "text_button_hover": "#fed7aa"
            },
            "Midnight": {
                "accent": "#8b5cf6",
                "bg": "#1e1b4b",
                "card_bg": "#312e81",
                "card_border": "#4338ca",
                "button_bg": "#8b5cf6",
                "button_fg": "#ffffff",
                "button_hover": "#7c3aed",
                "text": "#e0e7ff",
                "output_bg": "#000000",
                "output_fg": "#c4b5fd",
                "status_success": "#064e3b",
                "status_warning": "#78350f",
                "status_error": "#7f1d1d",
                "status_info": "#312e81",
                "text_button_bg": "#4338ca",
                "text_button_fg": "#e0e7ff",
                "text_button_hover": "#4f46e5"
            }
        }
        
        # Set default theme
        self.current_theme = "Light"
        self.apply_theme(self.current_theme)

        # Initialize variables
        self.init_variables()
        self.setup_gui()

    def update_widget_colors(self):
        # Update all frames and labels
        for widget in self.master.winfo_children():
            if isinstance(widget, (tk.Frame, tk.Label)):
                widget.configure(bg=self.bg)
                if isinstance(widget, tk.Label):
                    widget.configure(fg=self.text_color)
            elif isinstance(widget, ttk.Notebook):
                style = ttk.Style()
                style.configure("TNotebook", background=self.bg)
                style.configure("TNotebook.Tab", background=self.bg, foreground=self.text_color)
                style.map("TNotebook.Tab",
                    background=[("selected", self.accent)],
                    foreground=[("selected", self.button_fg)])

        # Update all text widgets and buttons in the application
        for widget in self.master.winfo_children():
            self._update_widget_tree(widget)

        # Update dashboard elements specifically
        if hasattr(self, 'dashboard_title'):
            self.dashboard_title.configure(bg=self.bg, fg=self.accent)
        if hasattr(self, 'dashboard_card'):
            self.dashboard_card.configure(bg=self.card_bg)
            self.style_card(self.dashboard_card)
        if hasattr(self, 'dashboard_welcome'):
            self.dashboard_welcome.configure(bg=self.card_bg, fg=self.text_color)
        if hasattr(self, 'dashboard_subtitle'):
            self.dashboard_subtitle.configure(bg=self.card_bg, fg=self.text_color)
        if hasattr(self, 'dashboard_rsa_desc'):
            self.dashboard_rsa_desc.configure(bg=self.card_bg, fg=self.text_color)
        if hasattr(self, 'dashboard_ecc_desc'):
            self.dashboard_ecc_desc.configure(bg=self.card_bg, fg=self.text_color)
        if hasattr(self, 'dashboard_rsa_btn'):
            self.style_button(self.dashboard_rsa_btn)
        if hasattr(self, 'dashboard_ecc_btn'):
            self.style_button(self.dashboard_ecc_btn)

    def _update_widget_tree(self, widget):
        # Update the current widget
        if isinstance(widget, tk.Text):
            widget.configure(bg=self.card_bg, fg=self.text_color, 
                           insertbackground=self.text_color)
        elif isinstance(widget, tk.Entry):
            widget.configure(bg=self.card_bg, fg=self.text_color,
                           insertbackground=self.text_color)
        elif isinstance(widget, tk.Button):
            if "Copy" in widget.cget("text") or "Export" in widget.cget("text"):
                self.style_button(widget, is_text_button=True)
            else:
                self.style_button(widget, is_text_button=False)
        elif isinstance(widget, (tk.Frame, tk.Label)):
            widget.configure(bg=self.bg)
            if isinstance(widget, tk.Label):
                widget.configure(fg=self.text_color)

        # Recursively update all child widgets
        for child in widget.winfo_children():
            self._update_widget_tree(child)

    def apply_theme(self, theme_name):
        theme = self.themes[theme_name]
        self.accent = theme["accent"]
        self.bg = theme["bg"]
        self.card_bg = theme["card_bg"]
        self.card_border = theme["card_border"]
        self.button_bg = theme["button_bg"]
        self.button_fg = theme["button_fg"]
        self.button_hover = theme["button_hover"]
        self.text_color = theme["text"]
        self.output_bg = theme["output_bg"]
        self.output_fg = theme["output_fg"]
        self.status_success = theme["status_success"]
        self.status_warning = theme["status_warning"]
        self.status_error = theme["status_error"]
        self.status_info = theme["status_info"]
        self.text_button_bg = theme["text_button_bg"]
        self.text_button_fg = theme["text_button_fg"]
        self.text_button_hover = theme["text_button_hover"]
        
        # Update all widgets
        self.master.configure(bg=self.bg)
        self.update_widget_colors()

        # Update output areas specifically
        if hasattr(self, 'rsa_output'):
            self.rsa_output.configure(bg=self.output_bg, fg=self.output_fg)
        if hasattr(self, 'ecc_output'):
            self.ecc_output.configure(bg=self.output_bg, fg=self.output_fg)
        if hasattr(self, 'rsa_key_display'):
            self.rsa_key_display.configure(bg=self.card_bg, fg=self.text_color)
        if hasattr(self, 'ecc_key_display'):
            self.ecc_key_display.configure(bg=self.card_bg, fg=self.text_color)

    def style_button(self, btn, is_text_button=False):
        if is_text_button:
            btn.configure(bg=self.text_button_bg, fg=self.text_button_fg, font=self.font_main, 
                         relief=tk.FLAT, bd=0, activebackground=self.text_button_hover, 
                         activeforeground=self.text_button_fg, cursor="hand2", highlightthickness=0)
            btn.bind("<Enter>", lambda e: btn.config(bg=self.text_button_hover))
            btn.bind("<Leave>", lambda e: btn.config(bg=self.text_button_bg))
        else:
            btn.configure(bg=self.button_bg, fg=self.button_fg, font=self.font_main, 
                         relief=tk.FLAT, bd=0, activebackground=self.button_hover, 
                         activeforeground=self.button_fg, cursor="hand2", highlightthickness=0)
            btn.bind("<Enter>", lambda e: btn.config(bg=self.button_hover))
            btn.bind("<Leave>", lambda e: btn.config(bg=self.button_bg))

    def style_entry(self, entry):
        entry.configure(bg=self.card_bg, fg=self.text_color, font=self.font_main, 
                       relief=tk.FLAT, bd=1, highlightbackground=self.card_border, 
                       highlightcolor=self.accent, insertbackground=self.text_color)

    def style_card(self, frame):
        frame.configure(bg=self.card_bg, bd=1, relief=tk.GROOVE, 
                       highlightbackground=self.card_border, highlightcolor=self.card_border, 
                       highlightthickness=1)

    def init_variables(self):
        # Font definitions
        self.font_main = ("Segoe UI", 12)
        self.font_title = ("Segoe UI", 20, "bold")
        self.font_section = ("Segoe UI", 14, "bold")
        self.font_code = ("Consolas", 10)

        # RSA variables
        self.p_var = tk.StringVar()
        self.q_var = tk.StringVar()
        self.message_var = tk.StringVar()
        self.public_key = None
        self.private_key = None
        self.encrypted_msg = None
        self.hashed = None
        self.decrypted_msg = None

        # ECC variables
        self.ecc_private_key = None
        self.ecc_public_key = None
        self.ecc_message_var = tk.StringVar()
        self.ecc_signature = None
        self.ecc_verified = None
        self.ecc_curve_var = tk.StringVar(value="NIST384p")
        self.ecc_curve_map = {
            "NIST192p": NIST192p,
            "NIST224p": NIST224p,
            "NIST256p": NIST256p,
            "NIST384p": NIST384p,
            "NIST521p": NIST521p
        }
        self.ecc_curve_obj = NIST384p

        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("")

    def setup_gui(self):
        self.setup_header()
        self.setup_tabs()
        self.setup_status_bar()
        self.setup_dashboard_gui()
        self.setup_rsa_gui()
        self.setup_ecc_gui()

    def setup_tabs(self):
        self.tab_control = ttk.Notebook(self.master)
        self.dashboard_tab = tk.Frame(self.tab_control, bg=self.bg)
        self.rsa_tab = tk.Frame(self.tab_control, bg=self.bg)
        self.ecc_tab = tk.Frame(self.tab_control, bg=self.bg)
        self.tab_control.add(self.dashboard_tab, text="Dashboard")
        self.tab_control.add(self.rsa_tab, text="RSA")
        self.tab_control.add(self.ecc_tab, text="ECC")
        self.tab_control.pack(expand=1, fill="both")

    def setup_status_bar(self):
        self.status_bar = tk.Label(self.master, textvariable=self.status_var, bd=1, 
                                 relief=tk.SUNKEN, anchor='w', bg=self.card_border, 
                                 font=self.font_main, fg=self.text_color)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def set_status(self, text, status_type="info"):
        self.status_var.set(text)
        colors = {
            "success": self.status_success,
            "warning": self.status_warning,
            "error": self.status_error,
            "info": self.status_info
        }
        self.status_bar.config(bg=colors.get(status_type, colors["info"]))

    def setup_dashboard_gui(self):
        tab = self.dashboard_tab
        self.dashboard_title = tk.Label(tab, text="Crypto GUI", font=self.font_title, bg=self.bg, 
                fg=self.accent)
        self.dashboard_title.pack(pady=(40, 10))
        
        self.dashboard_card = tk.Frame(tab, bg=self.card_bg)
        self.style_card(self.dashboard_card)
        self.dashboard_card.pack(pady=30, padx=30, ipadx=10, ipady=10)
        
        self.dashboard_welcome = tk.Label(self.dashboard_card, text="Welcome! This tool lets you experiment with RSA and ECC cryptography.",
                font=self.font_main, bg=self.card_bg, fg=self.text_color)
        self.dashboard_welcome.pack(pady=(10, 5), padx=20)
        
        self.dashboard_subtitle = tk.Label(self.dashboard_card, text="Choose a mode below to get started.",
                font=self.font_main, bg=self.card_bg, fg=self.text_color)
        self.dashboard_subtitle.pack(pady=(0, 20), padx=20)
        
        btn_frame = tk.Frame(self.dashboard_card, bg=self.card_bg)
        btn_frame.pack(pady=10)
        
        self.dashboard_rsa_btn = tk.Button(btn_frame, text="Go to RSA", width=16, 
                          command=lambda: self.tab_control.select(self.rsa_tab))
        self.style_button(self.dashboard_rsa_btn)
        self.dashboard_rsa_btn.grid(row=0, column=0, padx=20, pady=10)
        ToolTip(self.dashboard_rsa_btn, "Switch to RSA encryption, decryption, and key management.")
        
        self.dashboard_ecc_btn = tk.Button(btn_frame, text="Go to ECC", width=16, 
                          command=lambda: self.tab_control.select(self.ecc_tab))
        self.style_button(self.dashboard_ecc_btn)
        self.dashboard_ecc_btn.grid(row=0, column=1, padx=20, pady=10)
        ToolTip(self.dashboard_ecc_btn, "Switch to ECC encryption, decryption, and key management.")

        self.dashboard_rsa_desc = tk.Label(self.dashboard_card, text="\u2022 RSA: Asymmetric encryption, digital signatures, and key generation using two large primes.",
                    font=self.font_main, bg=self.card_bg, fg=self.text_color, anchor='w')
        self.dashboard_rsa_desc.pack(pady=(20, 0), padx=30, anchor='w')
        
        self.dashboard_ecc_desc = tk.Label(self.dashboard_card, text="\u2022 ECC: Elliptic Curve Cryptography for digital signatures and secure key exchange.",
                    font=self.font_main, bg=self.card_bg, fg=self.text_color, anchor='w')
        self.dashboard_ecc_desc.pack(pady=(0, 0), padx=30, anchor='w')

    def setup_rsa_gui(self):
        tab = self.rsa_tab
        tk.Label(tab, text="RSA Crypto", font=self.font_title, bg=self.bg, fg=self.accent).pack(pady=(30, 10))
        
        card = tk.Frame(tab, bg=self.card_bg)
        self.style_card(card)
        card.pack(pady=20, padx=30, ipadx=10, ipady=10, fill=tk.X)
        
        # Key Generation Section
        tk.Label(card, text="Key Generation", font=self.font_section, 
                bg=self.card_bg, fg=self.text_color).grid(row=0, column=0, columnspan=4, pady=(10, 10), sticky='w')
        
        # Input fields with better spacing and labels
        input_frame = tk.Frame(card, bg=self.card_bg)
        input_frame.grid(row=1, column=0, columnspan=4, sticky='w', padx=5, pady=5)
        
        # Prime p input
        p_frame = tk.Frame(input_frame, bg=self.card_bg)
        p_frame.pack(side=tk.LEFT, padx=(0, 20))
        tk.Label(p_frame, text="Prime p:", font=self.font_main, bg=self.card_bg, fg=self.text_color).pack(side=tk.LEFT, padx=(0, 5))
        p_entry = tk.Entry(p_frame, textvariable=self.p_var, width=15)
        self.style_entry(p_entry)
        p_entry.pack(side=tk.LEFT)
        ToolTip(p_entry, "Enter a prime number for p (e.g., 17, 19, 23...)")
        
        # Prime q input
        q_frame = tk.Frame(input_frame, bg=self.card_bg)
        q_frame.pack(side=tk.LEFT, padx=(0, 20))
        tk.Label(q_frame, text="Prime q:", font=self.font_main, bg=self.card_bg, fg=self.text_color).pack(side=tk.LEFT, padx=(0, 5))
        q_entry = tk.Entry(q_frame, textvariable=self.q_var, width=15)
        self.style_entry(q_entry)
        q_entry.pack(side=tk.LEFT)
        ToolTip(q_entry, "Enter a different prime number for q (e.g., 29, 31, 37...)")

        # Buttons in a separate frame
        button_frame = tk.Frame(card, bg=self.card_bg)
        button_frame.grid(row=2, column=0, columnspan=4, sticky='w', padx=5, pady=5)
        
        # Generate Keys button
        gen_btn = tk.Button(button_frame, text="Generate Keys", width=15, command=self.generate_keys)
        self.style_button(gen_btn)
        gen_btn.pack(side=tk.LEFT, padx=(0, 10))
        ToolTip(gen_btn, "Generate RSA public and private keys using the provided primes.")
        
        # Load Message button
        file_btn = tk.Button(button_frame, text="Load Message from File", width=20, command=self.load_rsa_message_file)
        self.style_button(file_btn)
        file_btn.pack(side=tk.LEFT)
        ToolTip(file_btn, "Load a message from a text file.")

        # Key display
        self.rsa_key_display = tk.Text(card, height=3, width=70, bg="#f9fafb", 
                                      font=self.font_code, bd=1, relief=tk.SUNKEN)
        self.rsa_key_display.grid(row=3, column=0, columnspan=3, padx=5, pady=5)
        self.rsa_key_display.config(state='disabled')
        
        copy_keys_btn = tk.Button(card, text="Copy Keys", width=12, command=self.copy_rsa_keys)
        self.style_button(copy_keys_btn, is_text_button=True)
        copy_keys_btn.grid(row=3, column=3, padx=5, pady=5)
        ToolTip(copy_keys_btn, "Copy the generated RSA keys to clipboard.")

        # Message section
        msg_frame = tk.Frame(card, bg=self.card_bg)
        msg_frame.grid(row=4, column=0, columnspan=4, sticky='w', padx=5, pady=5)
        
        tk.Label(msg_frame, text="Message:", font=self.font_main, bg=self.card_bg).pack(side=tk.LEFT, padx=(0, 5))
        msg_entry = tk.Entry(msg_frame, textvariable=self.message_var, width=50)
        self.style_entry(msg_entry)
        msg_entry.pack(side=tk.LEFT)
        ToolTip(msg_entry, "Enter the message to encrypt, decrypt, or verify.")

        # Operation buttons
        op_frame = tk.Frame(card, bg=self.card_bg)
        op_frame.grid(row=5, column=0, columnspan=4, sticky='w', padx=5, pady=5)
        
        operations = [
            ("Encrypt", self.encrypt_message, "Encrypt the message using the public key."),
            ("Decrypt", self.decrypt_message, "Decrypt the encrypted message using the private key."),
            ("Verify", self.verify_message, "Verify the decrypted message matches the original."),
            ("Clear Output", self.clear_rsa_output, "Clear the RSA output area."),
            ("Export Output to File", self.export_rsa_output, "Save the output to a text file.")
        ]
        
        for text, command, tooltip in operations:
            btn = tk.Button(op_frame, text=text, width=20 if "Export" in text else 15, command=command)
            self.style_button(btn)
            btn.pack(side=tk.LEFT, padx=(0, 10))
            ToolTip(btn, tooltip)

        # Output section
        output_frame = tk.Frame(card, bg=self.card_bg, bd=1, relief=tk.GROOVE)
        output_frame.grid(row=6, column=0, columnspan=4, padx=5, pady=(10, 10), sticky='nsew')
        
        tk.Label(output_frame, text="Output", font=self.font_section, 
                bg=self.card_bg).pack(anchor='w', padx=5, pady=(5, 0))
        
        self.rsa_output = scrolledtext.ScrolledText(output_frame, width=90, height=10, 
                                                  state='disabled', bg="#222831", fg="#eeeeee", 
                                                  font=self.font_code, bd=0)
        self.rsa_output.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        
        copy_output_btn = tk.Button(output_frame, text="Copy Output", width=12, 
                                  command=self.copy_rsa_output)
        self.style_button(copy_output_btn)
        copy_output_btn.pack(anchor='e', padx=5, pady=5)
        ToolTip(copy_output_btn, "Copy the RSA output to clipboard.")

    def load_rsa_message_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "r", encoding="utf-8") as f:
                self.message_var.set(f.read())
            self.set_status(f"Loaded message from {os.path.basename(file_path)}", "success")

    def export_rsa_output(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(self.rsa_output.get("1.0", tk.END))
            self.set_status(f"Output exported to {os.path.basename(file_path)}", "success")

    def copy_rsa_output(self):
        output = self.rsa_output.get('1.0', tk.END)
        pyperclip.copy(output)
        self.set_status("Output copied to clipboard.", "success")

    def copy_rsa_keys(self):
        if self.public_key and self.private_key:
            keys = f"Public key: {self.public_key}\nPrivate key: {self.private_key}"
            pyperclip.copy(keys)
            self.set_status("Keys copied to clipboard.", "success")
        else:
            self.set_status("No keys to copy.", "warning")

    def generate_keys(self):
        try:
            p = int(self.p_var.get())
            q = int(self.q_var.get())
            self.public_key, self.private_key = generate_keypair(p, q)
            self.rsa_key_display.config(state='normal')
            self.rsa_key_display.delete('1.0', tk.END)
            self.rsa_key_display.insert(tk.END, f"Public key: {self.public_key}\nPrivate key: {self.private_key}")
            self.rsa_key_display.config(state='disabled')
            self.log_rsa(f"Public key: {self.public_key}\nPrivate key: {self.private_key}")
            self.set_status("RSA keys generated.", "success")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.set_status("Key generation failed.", "error")

    def encrypt_message(self):
        if not self.public_key:
            messagebox.showwarning("Warning", "Generate keys first!")
            self.set_status("No keys.", "warning")
            return
        message = self.message_var.get()
        if not message:
            messagebox.showwarning("Warning", "Enter a message!")
            self.set_status("No message.", "warning")
            return
        self.hashed = hashFunction(message)
        self.encrypted_msg = encrypt(self.public_key, message)  # Encrypt with public key
        self.log_rsa(f"Original message: {message}")
        self.log_rsa(f"Hash of message: {self.hashed}")
        self.log_rsa(f"Encrypted message: {self.encrypted_msg}")
        self.set_status("Message encrypted.", "success")

    def decrypt_message(self):
        if not self.private_key or not self.encrypted_msg:
            messagebox.showwarning("Warning", "Generate keys and encrypt a message first!")
            self.set_status("No encrypted message.", "warning")
            return
        self.decrypted_msg = decrypt(self.private_key, self.encrypted_msg)  # Decrypt with private key
        self.log_rsa(f"Decrypted message: {self.decrypted_msg}")
        self.set_status("Message decrypted.", "success")

    def verify_message(self):
        if not self.decrypted_msg:
            messagebox.showwarning("Warning", "Decrypt a message first!")
            self.set_status("No decrypted message.", "warning")
            return
        message = self.message_var.get()
        if not message:
            messagebox.showwarning("Warning", "Enter the original message!")
            self.set_status("No message.", "warning")
            return
        current_hash = hashFunction(message)
        decrypted_hash = hashFunction(self.decrypted_msg)
        if current_hash == decrypted_hash:
            self.log_rsa(f"Verification successful!\nOriginal hash: {current_hash}\nDecrypted hash: {decrypted_hash}")
            self.set_status("Verification successful.", "success")
        else:
            self.log_rsa(f"Verification failed!\nOriginal hash: {current_hash}\nDecrypted hash: {decrypted_hash}")
            self.set_status("Verification failed.", "error")

    def clear_rsa_output(self):
        self.rsa_output.config(state='normal')
        self.rsa_output.delete('1.0', tk.END)
        self.rsa_output.config(state='disabled')
        self.set_status("", "info")

    def log_rsa(self, text):
        self.rsa_output.config(state='normal')
        self.rsa_output.insert(tk.END, text + '\n')
        self.rsa_output.see(tk.END)
        self.rsa_output.config(state='disabled')

    def setup_ecc_gui(self):
        tab = self.ecc_tab
        tk.Label(tab, text="ECC Crypto", font=self.font_title, bg=self.bg, fg=self.accent).pack(pady=(30, 10))
        card = tk.Frame(tab, bg=self.card_bg)
        self.style_card(card)
        card.pack(pady=20, padx=30, ipadx=10, ipady=10, fill=tk.X)
        section = tk.Label(card, text="Key Generation", font=self.font_section, bg=self.card_bg, fg="#222")
        section.grid(row=0, column=0, columnspan=7, pady=(10, 10), sticky='w')
        tk.Label(card, text="Curve:", font=self.font_main, bg=self.card_bg).grid(row=1, column=0, sticky='e', padx=5, pady=5)
        curve_menu = ttk.Combobox(card, textvariable=self.ecc_curve_var, values=list(self.ecc_curve_map.keys()), state="readonly", font=self.font_main, width=12)
        curve_menu.grid(row=1, column=1, sticky='w', padx=5, pady=5)
        ToolTip(curve_menu, "Select the elliptic curve for ECC key generation.")
        gen_ecc_btn = tk.Button(card, text="Generate ECC Keys", width=15, command=self.generate_ecc_keys)
        self.style_button(gen_ecc_btn)
        gen_ecc_btn.grid(row=1, column=2, padx=8, pady=5)
        ToolTip(gen_ecc_btn, "Generate ECC private and public keys.")
        # File picker for message
        file_btn = tk.Button(card, text="Load Message from File", width=20, command=self.load_ecc_message_file)
        self.style_button(file_btn)
        file_btn.grid(row=1, column=3, padx=8, pady=5)
        ToolTip(file_btn, "Load a message from a text file.")
        self.ecc_key_display = tk.Text(card, height=5, width=70, bg="#f9fafb", font=self.font_code, bd=1, relief=tk.SUNKEN)
        self.ecc_key_display.grid(row=2, column=0, columnspan=6, padx=5, pady=5)
        self.ecc_key_display.config(state='disabled')
        copy_ecc_keys_btn = tk.Button(card, text="Copy Keys", width=12, command=self.copy_ecc_keys)
        self.style_button(copy_ecc_keys_btn, is_text_button=True)
        copy_ecc_keys_btn.grid(row=2, column=6, padx=5, pady=5)
        ToolTip(copy_ecc_keys_btn, "Copy the generated ECC keys to clipboard.")
        tk.Label(card, text="Message:", font=self.font_main, bg=self.card_bg).grid(row=3, column=0, sticky='e', padx=5, pady=5)
        ecc_msg_entry = tk.Entry(card, textvariable=self.ecc_message_var, width=50)
        self.style_entry(ecc_msg_entry)
        ecc_msg_entry.grid(row=3, column=1, columnspan=4, sticky='w', padx=5, pady=5)
        ToolTip(ecc_msg_entry, "Enter the message to sign or verify.")
        sign_btn = tk.Button(card, text="Sign", width=15, command=self.ecc_sign_message)
        self.style_button(sign_btn)
        sign_btn.grid(row=4, column=0, padx=8, pady=5)
        ToolTip(sign_btn, "Sign the message using the ECC private key.")
        verify_ecc_btn = tk.Button(card, text="Verify", width=15, command=self.ecc_verify_message)
        self.style_button(verify_ecc_btn)
        verify_ecc_btn.grid(row=4, column=1, padx=8, pady=5)
        ToolTip(verify_ecc_btn, "Verify the ECC signature for the message.")
        clear_ecc_btn = tk.Button(card, text="Clear Output", width=15, command=self.clear_ecc_output)
        self.style_button(clear_ecc_btn)
        clear_ecc_btn.grid(row=4, column=2, padx=8, pady=5)
        ToolTip(clear_ecc_btn, "Clear the ECC output area.")
        # File export for output
        export_btn = tk.Button(card, text="Export Output to File", width=20, command=self.export_ecc_output)
        self.style_button(export_btn)
        export_btn.grid(row=4, column=3, padx=8, pady=5)
        ToolTip(export_btn, "Save the output to a text file.")
        output_frame = tk.Frame(card, bg=self.card_bg, bd=1, relief=tk.GROOVE)
        output_frame.grid(row=5, column=0, columnspan=7, padx=5, pady=(10, 10), sticky='nsew')
        tk.Label(output_frame, text="Output", font=self.font_section, bg=self.card_bg).pack(anchor='w', padx=5, pady=(5, 0))
        self.ecc_output = scrolledtext.ScrolledText(output_frame, width=90, height=10, state='disabled', bg="#222831", fg="#eeeeee", font=self.font_code, bd=0)
        self.ecc_output.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        copy_ecc_output_btn = tk.Button(output_frame, text="Copy Output", width=12, command=self.copy_ecc_output)
        self.style_button(copy_ecc_output_btn)
        copy_ecc_output_btn.pack(anchor='e', padx=5, pady=5)
        ToolTip(copy_ecc_output_btn, "Copy the ECC output to clipboard.")

    def load_ecc_message_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "r", encoding="utf-8") as f:
                self.ecc_message_var.set(f.read())
            self.set_status(f"Loaded message from {os.path.basename(file_path)}", "success")

    def export_ecc_output(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(self.ecc_output.get("1.0", tk.END))
            self.set_status(f"Output exported to {os.path.basename(file_path)}", "success")

    def copy_ecc_output(self):
        output = self.ecc_output.get('1.0', tk.END)
        pyperclip.copy(output)
        self.set_status("Output copied to clipboard.", "success")

    def copy_ecc_keys(self):
        if self.ecc_private_key and self.ecc_public_key:
            keys = f"Private key: {self.ecc_private_key.to_pem().decode()}\nPublic key: {self.ecc_public_key.to_pem().decode()}"
            pyperclip.copy(keys)
            self.set_status("ECC keys copied to clipboard.", "success")
        else:
            self.set_status("No ECC keys to copy.", "warning")





#? ---------------------------------------------------------------------------------------------------------- #
#?                                              ECC Algorithm                                                 #
#? ---------------------------------------------------------------------------------------------------------- #





#* ------------------------------- Generate Keys ------------------------------ #


    def generate_ecc_keys(self):
        curve_name = self.ecc_curve_var.get()
        curve_obj = self.ecc_curve_map.get(curve_name, NIST384p)
        if SigningKey is None or curve_obj is None:
            messagebox.showerror("Error", "ecdsa library not installed or incomplete. Please install with 'pip install ecdsa'.")
            self.set_status("ECC unavailable.", "error")
            return
        try:
            self.ecc_private_key = SigningKey.generate(curve=curve_obj)         #! Generate ECC private key
            self.ecc_public_key = self.ecc_private_key.get_verifying_key()      #! Get ECC public key form private key
            priv_pem = self.ecc_private_key.to_pem()
            pub_pem = self.ecc_public_key.to_pem()
            try:
                priv_pem_str = priv_pem.decode("utf-8")
            except Exception:
                priv_pem_str = str(priv_pem)
            try:
                pub_pem_str = pub_pem.decode("utf-8")
            except Exception:
                pub_pem_str = str(pub_pem)
            key_details = f"Curve: {curve_name}\nKey size: {self.ecc_private_key.curve.baselen * 8} bits"
            self.ecc_key_display.config(state='normal')
            self.ecc_key_display.delete('1.0', tk.END)
            self.ecc_key_display.insert(tk.END, f"{key_details}\nPrivate key: {priv_pem_str}\nPublic key: {pub_pem_str}")
            self.ecc_key_display.config(state='disabled')
            self.log_ecc(f"ECC keys generated for {curve_name}.")
            self.set_status("ECC keys generated.", "success")
        except Exception as e:
            messagebox.showerror("ECC Key Error", f"Failed to generate ECC keys: {e}")
            self.set_status("ECC key generation failed.", "error")





#* ------------------------------- Sign Message ------------------------------- #


    def ecc_sign_message(self):
        if not self.ecc_private_key:
            messagebox.showwarning("Warning", "Generate ECC keys first!")
            self.set_status("No ECC keys.", "warning")
            return
        message = self.ecc_message_var.get()
        if not message:
            messagebox.showwarning("Warning", "Enter a message!")
            self.set_status("No message.", "warning")
            return
        msg_bytes = message.encode('utf-8')                                         #! Convert message to bytes and sign
        self.ecc_signature = self.ecc_private_key.sign(msg_bytes)
        sig_hex = self.ecc_signature.hex()                                          #! Convert signature to hex         
        sig_b64 = base64.b64encode(self.ecc_signature).decode('utf-8')              #! Convert signature to base64
        self.log_ecc(f"Message: {message}")     
        self.log_ecc(f"Signature (hex): {sig_hex}")
        self.log_ecc(f"Signature (base64): {sig_b64}")
        self.set_status("Message signed.", "success")

    def ecc_verify_message(self):
        if not self.ecc_public_key or not self.ecc_signature:
            messagebox.showwarning("Warning", "Sign a message first!")
            self.set_status("No signature.", "warning")
            return
        message = self.ecc_message_var.get()
        if not message:
            messagebox.showwarning("Warning", "Enter the original message!")
            self.set_status("No message.", "warning")
            return
        msg_bytes = message.encode('utf-8')
        try:
            if self.ecc_public_key.verify(self.ecc_signature, msg_bytes):
                self.log_ecc("Signature verification successful!")
                self.set_status("ECC verification successful.", "success")
            else:
                self.log_ecc("Signature verification failed!")
                self.set_status("ECC verification failed.", "error")
        except BadSignatureError:
            self.log_ecc("Signature verification failed!")
            self.set_status("ECC verification failed.", "error")

    def clear_ecc_output(self):
        self.ecc_output.config(state='normal')
        self.ecc_output.delete('1.0', tk.END)
        self.ecc_output.config(state='disabled')
        self.set_status("", "info")

    def log_ecc(self, text):
        self.ecc_output.config(state='normal')
        self.ecc_output.insert(tk.END, text + '\n')
        self.ecc_output.see(tk.END)
        self.ecc_output.config(state='disabled')

    def setup_header(self):
        header = tk.Frame(self.master, bg=self.bg)
        header.pack(side=tk.TOP, fill=tk.X)
        
        # Logo and title
        try:
            self.logo_img = PhotoImage(file=os.path.join(os.path.dirname(__file__), "crypto_icon.png"))
            logo = tk.Label(header, image=self.logo_img, bg=self.bg)
        except Exception:
            logo = tk.Label(header, text="🔒", font=("Segoe UI", 28), bg=self.bg)
        logo.pack(side=tk.LEFT, padx=(20, 10), pady=10)
        
        title = tk.Label(header, text="Crypto GUI", font=self.font_title, bg=self.bg, fg=self.accent)
        title.pack(side=tk.LEFT, pady=10)
        
        # Theme switcher
        theme_frame = tk.Frame(header, bg=self.bg)
        theme_frame.pack(side=tk.RIGHT, padx=20, pady=10)
        
        theme_label = tk.Label(theme_frame, text="Theme:", font=self.font_main, bg=self.bg, fg=self.text_color)
        theme_label.pack(side=tk.LEFT, padx=(0, 5))
        
        theme_menu = ttk.Combobox(theme_frame, values=list(self.themes.keys()), 
                                 state="readonly", font=self.font_main, width=10)
        theme_menu.set(self.current_theme)
        theme_menu.pack(side=tk.LEFT)
        theme_menu.bind("<<ComboboxSelected>>", lambda e: self.apply_theme(theme_menu.get()))
        ToolTip(theme_menu, "Select a color theme for the application")

if __name__ == "__main__":
    try:
        import pyperclip
    except ImportError:
        messagebox.showerror("Error", "pyperclip library not installed. Please install with 'pip install pyperclip'.")
        exit(1)
    root = tk.Tk()
    app = CryptoGUI(root)
    root.mainloop()