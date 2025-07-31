import customtkinter
from tkinter import filedialog, messagebox
from math import gcd
import time
from PIL import Image, ImageTk
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii
import random
from itertools import cycle
from string import ascii_letters

# Window dimensions
WINDOW_WIDTH = 1000
WINDOW_HEIGHT = 700

def center_window(window):
    """Center the window on screen"""
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width - WINDOW_WIDTH) // 2
    y = (screen_height - WINDOW_HEIGHT) // 2
    window.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}+{x}+{y}")

# ================== Splash Screen with Vibes ==================
def show_splash():
    splash = customtkinter.CTk()
    splash.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
    center_window(splash)
    splash.overrideredirect(True)  # Remove window decorations
    splash.configure(bg="#000000")

    # Create splash frame with gradient background
    splash_frame = customtkinter.CTkFrame(master=splash, fg_color="transparent")
    splash_frame.pack(fill="both", expand=True)

    # Add animated background
    canvas = customtkinter.CTkCanvas(splash_frame, bg='black', highlightthickness=0)
    canvas.pack(fill="both", expand=True)

    # Create floating particles
    particles = []
    colors = ['#4CC9F0', '#F72585', '#7209B7', '#3A0CA3', '#4361EE']
    for _ in range(100):
        x = random.randint(0, WINDOW_WIDTH)
        y = random.randint(0, WINDOW_HEIGHT)
        size = random.randint(1, 3)
        color = random.choice(colors)
        particle = canvas.create_oval(x, y, x+size, y+size, fill=color, outline="")
        particles.append((particle, x, y, size, color))

    # Add splash content - MODIFIED TO REMOVE BOXES
    title_label = customtkinter.CTkLabel(
        master=canvas,  # Changed from splash_frame to canvas
        text="CRYPTOGRAPHY SYSTEM", 
        font=("Roboto", 48, "bold"),
        text_color="#4CC9F0",
        bg_color="black",  # Set background to match splash
        fg_color="transparent"  # Make foreground transparent
    )
    title_label.place(relx=0.5, rely=0.4, anchor="center")

    loading_label = customtkinter.CTkLabel(
        master=canvas,  # Changed from splash_frame to canvas
        text="Loading...", 
        font=("Roboto", 24),
        text_color="#F72585",
        bg_color="black",  # Set background to match splash
        fg_color="transparent"  # Make foreground transparent
    )
    loading_label.place(relx=0.5, rely=0.5, anchor="center")

    progress = customtkinter.CTkProgressBar(master=canvas, orientation="horizontal", width=500, height=20)
    progress.place(relx=0.5, rely=0.6, anchor="center")
    progress.set(0)

    version_label = customtkinter.CTkLabel(
        master=canvas,  # Changed from splash_frame to canvas
        text="Version 1.0", 
        font=("Roboto", 16),
        text_color="#7209B7",
        bg_color="black",  # Set background to match splash
        fg_color="transparent"  # Make foreground transparent
    )
    version_label.place(relx=0.5, rely=0.9, anchor="center")

    # Animation functions
    def move_particles():
        for i, (particle, x, y, size, color) in enumerate(particles):
            # Move particles diagonally
            new_x = (x + 1) % WINDOW_WIDTH
            new_y = (y + 1) % WINDOW_HEIGHT
            canvas.coords(particle, new_x, new_y, new_x+size, new_y+size)
            particles[i] = (particle, new_x, new_y, size, color)
        splash.after(30, move_particles)

    def pulse_title():
        current_size = title_label.cget("font")[1]
        new_size = current_size + 1 if current_size < 52 else 48
        title_label.configure(font=("Roboto", new_size, "bold"))
        splash.after(100, pulse_title)

    # Start animations
    move_particles()
    pulse_title()

    # Animate progress bar
    for i in range(101):
        progress.set(i/100)
        splash.update()
        time.sleep(0.02)

    splash.destroy()

# Start the application by showing splash first
show_splash()

def convert_key_to_matrix(key):
    key = key.upper()
    if not key.isalpha():
        return None
    key_length = len(key)
    matrix_size = int(key_length ** 0.5)
    if matrix_size * matrix_size != key_length:
        return None
    key_matrix = [[0 for _ in range(matrix_size)] for _ in range(matrix_size)]
    index = 0
    for i in range(matrix_size):
        for j in range(matrix_size):
            key_matrix[i][j] = ord(key[index]) - ord('A')
            index += 1
    return key_matrix

def convert_key_to_numbers(key):
    key = key.upper()
    if not key.isalpha():
        return None
    return [ord(char) - ord('A') + 1 for char in key]


def clear_frame():
    for widget in frame.winfo_children():
        widget.destroy()

# ================== Main Application ==================
customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")

# Create main window with better styling
root = customtkinter.CTk()
root.geometry("700x600")
root.title("Cryptography System")
root.configure(bg="#1A1A2E")

# Make window centered
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x = (screen_width - 700) // 2
y = (screen_height - 600) // 2
root.geometry(f"700x600+{x}+{y}")

# ================== Enhanced GUI Functions ==================

def clear_frame():
    for widget in frame.winfo_children():
        widget.destroy()

def create_nav_button(master, text, command, color="#F72585"):
    return customtkinter.CTkButton(
        master=master,
        text=text,
        command=command,
        fg_color=color,
        hover_color="#B5179E",
        font=("Roboto", 14, "bold"),
        corner_radius=10,
        width=200,
        height=40
    )

def create_action_button(master, text, command, color="#4CC9F0"):
    return customtkinter.CTkButton(
        master=master,
        text=text,
        command=command,
        fg_color=color,
        hover_color="#4895EF",
        font=("Roboto", 12),
        corner_radius=8,
        width=120
    )

def create_entry(master):
    return customtkinter.CTkEntry(
        master=master,
        font=("Roboto", 12),
        border_color="#7209B7",
        fg_color="#16213E",
        corner_radius=8,
        width=250
    )

def create_label(master, text, size=12, color="#F8F9FA"):
    return customtkinter.CTkLabel(
        master=master,
        text=text,
        font=("Roboto", size),
        text_color=color
    )

# ================== Home Scene ==================

def open_home_scene():
    clear_frame()

    # Configure grid weights to center content
    frame.grid_rowconfigure(0, weight=1)  # Top space
    frame.grid_rowconfigure(1, weight=0)  # Title row (no weight)
    frame.grid_rowconfigure(2, weight=0)  # Subtitle row (no weight)
    frame.grid_rowconfigure(3, weight=1)  # Button container space
    frame.grid_rowconfigure(4, weight=1)  # Bottom space
    frame.grid_columnconfigure(0, weight=1)  # Left space
    frame.grid_columnconfigure(1, weight=1)  # Right space

    # Create a container for the centered content
    content_frame = customtkinter.CTkFrame(frame, fg_color="transparent")
    content_frame.grid(row=1, column=0, rowspan=3, columnspan=2, sticky="nsew")
    
    # Configure content frame grid
    content_frame.grid_rowconfigure(0, weight=0)
    content_frame.grid_rowconfigure(1, weight=0)
    content_frame.grid_rowconfigure(2, weight=0)
    content_frame.grid_columnconfigure(0, weight=1)
    content_frame.grid_columnconfigure(1, weight=1)

    # Title with gradient effect
    title_label = customtkinter.CTkLabel(
        master=content_frame, 
        text="CRYPTOGRAPHY SYSTEM", 
        font=("Roboto", 32, "bold"),
        text_color="#4CC9F0"
    )
    title_label.grid(row=0, column=0, columnspan=2, pady=(0, 10), padx=10)

    # Subtitle
    subtitle_label = create_label(content_frame, "Choose An Algorithm", 20, "#F72585")
    subtitle_label.grid(row=1, column=0, columnspan=2, pady=(0, 30), padx=10)

    # Algorithm buttons arranged in a grid with colors
    buttons = [
        ("Transposition Cipher", "#7209B7", open_transposition_scene),
        ("Rot13", "#3A0CA3", open_rot13_scene),
        ("Caesar Cipher", "#4361EE", open_caesar_scene),
        ("Substitution Cipher", "#4895EF", open_substitution_scene),
        ("Hill Cipher", "#4CC9F0", open_hill_scene),
        ("Affine Cipher", "#F72585", open_affine_scene),
        ("Rail Fence Cipher", "#4361EE", open_railfence_scene),
         ("Play Fair", "#008080", open_playfair_scene),
        ("Rivest Shamir Adleman(RSA)", "#e377c2", open_rsa_scene),
         ("Diffie Hellman", "#CD5C5C", open_diffie_hellman_scene) 
    ]

    for i, (text, color, command) in enumerate(buttons):
        btn = create_nav_button(content_frame, text, command, color)
        row = 2 + (i // 2)
        col = i % 2
        btn.grid(row=row, column=col, pady=10, padx=20, sticky="nsew")

#Hill cipher///////////////////////////
def update_result(entry, result):
    entry.delete(0, 'end') 
    entry.insert(0, result) 

def open_hill_scene():
    clear_frame()

    # Title
    title_label = customtkinter.CTkLabel(
        master=frame,
        text="HILL CIPHER",
        font=("Roboto", 28, "bold"),
        text_color="#4CC9F0"
    )
    title_label.grid(row=0, column=0, columnspan=2, pady=(30, 10))

    # Message Label + Entry
    message_label = create_label(frame, "Message:", 14)
    message_label.grid(row=1, column=0, sticky="e", padx=10, pady=10)

    message_entry = create_entry(frame)
    message_entry.grid(row=1, column=1, padx=10, pady=10)

    # Key Label + Entry
    key_label = create_label(frame, "Key:", 14)
    key_label.grid(row=2, column=0, sticky="e", padx=10, pady=10)

    key_entry = create_entry(frame)
    key_entry.grid(row=2, column=1, padx=10, pady=10)

    # Result Label + Entry
    result_label = create_label(frame, "Result:", 14)
    result_label.grid(row=3, column=0, sticky="e", padx=10, pady=10)

    result_entry = create_entry(frame)
    result_entry.grid(row=3, column=1, padx=10, pady=10)

    # Buttons: Encrypt & Decrypt
    button_frame = customtkinter.CTkFrame(master=frame, fg_color="transparent")
    button_frame.grid(row=4, column=0, columnspan=2, pady=20)



    encrypt_button = create_action_button(
        master=button_frame,
        text="Encrypt",
        command=lambda: update_result(result_entry, encrypt_hill(message_entry.get(), key_entry.get())),
        color="#7209B7"
    )
    encrypt_button.pack(side="left", padx=10)

    # Decrypt Button with update_result
    decrypt_button = create_action_button(
        master=button_frame,
        text="Decrypt",
        command=lambda: update_result(result_entry, decrypt_hill(message_entry.get(), key_entry.get())),
        color="#3A0CA3"
    )
    decrypt_button.pack(side="left", padx=10)

    # Upload & Download Buttons
    upload_button = create_action_button(
        master=frame,
        text="Upload File",
        command=lambda: upload_file_hill(message_entry),
        color="#4895EF"
    )
    upload_button.grid(row=5, column=0, columnspan=2, pady=10)

    download_button = create_action_button(
        master=frame,
        text="Download Result",
        command=lambda: download_file(result_entry.get()),
        color="#4CC9F0"
    )
    download_button.grid(row=6, column=0, columnspan=2, pady=10)

    # Home Button
    home_button = create_nav_button(
        master=frame,
        text="Back to Home",
        command=open_home_scene,
        color="#F72585"
    )
    home_button.grid(row=7, column=0, columnspan=2, pady=20)


def convert_key_to_matrix(key):

    key = key.upper()
    if not key.isalpha():
        return None
    length = int(len(key) ** 0.5)
    if length * length != len(key):
        return None
    matrix, idx = [], 0
    for _ in range(length):
        row = [ord(key[idx + j]) - ord('A') for j in range(length)]
        matrix.append(row)
        idx += length
    return matrix

def check_invalid_input(text, input_type):
    if any(char.isdigit() for char in text):
        return f"Error: {input_type} must not contain numbers."
    
    if input_type == "Key":
        if any(not char.isalpha() for char in text):
            return f"Error: {input_type} must contain letters only (no symbols or spaces)."
    else:  # Message
        if any(not (char.isalpha() or char.isspace()) for char in text):
            return f"Error: {input_type} must not contain symbols."
    
    return None

def encrypt_hill(message, key):
    error = check_invalid_input(message, "Message")
    if error: return error
    error = check_invalid_input(key, "Key")
    if error: return error

    key_matrix = convert_key_to_matrix(key)
    if key_matrix is None:
        return "Error: Key must be a square matrix of letters only."

    message = message.replace(" ", "").upper()  # Remove spaces before processing
    while len(message) % len(key_matrix) != 0:
        message += 'X'

    size = len(key_matrix)
    blocks = [[ord(char) - ord('A') for char in message[i:i+size]] for i in range(0, len(message), size)]
    encrypted_matrix = []
    for block in blocks:
        encrypted = []
        for i in range(size):
            val = sum(block[j] * key_matrix[i][j] for j in range(size)) % 26
            encrypted.append(val)
        encrypted_matrix.extend(encrypted)
    return ''.join(chr(c + ord('A')) for c in encrypted_matrix)

def decrypt_hill(message, key):
    error = check_invalid_input(message, "Message")
    if error: return error
    error = check_invalid_input(key, "Key")
    if error: return error

    key_matrix = convert_key_to_matrix(key)
    if key_matrix is None:
        return "Error: Key matrix must be 2x2 or 3x3."

    message = message.replace(" ", "").upper()
    size = len(key_matrix)
    if size not in (2, 3):
        return "Error: Key matrix must be 2x2 or 3x3."

    try:
        if size == 2:
            a, b = key_matrix[0]
            c, d = key_matrix[1]
            det = (a * d - b * c) % 26
            inv_det = pow(det, -1, 26)
            inv = [[d * inv_det % 26, -b * inv_det % 26],
                   [-c * inv_det % 26, a * inv_det % 26]]
        else:
            a = key_matrix
            det = (
                a[0][0]*(a[1][1]*a[2][2] - a[1][2]*a[2][1]) -
                a[0][1]*(a[1][0]*a[2][2] - a[1][2]*a[2][0]) +
                a[0][2]*(a[1][0]*a[2][1] - a[1][1]*a[2][0])
            ) % 26
            inv_det = pow(det, -1, 26)
            cof = [
                [a[1][1]*a[2][2] - a[1][2]*a[2][1], -(a[0][1]*a[2][2] - a[0][2]*a[2][1]), a[0][1]*a[1][2] - a[0][2]*a[1][1]],
                [-(a[1][0]*a[2][2] - a[1][2]*a[2][0]), a[0][0]*a[2][2] - a[0][2]*a[2][0], -(a[0][0]*a[1][2] - a[0][2]*a[1][0])],
                [a[1][0]*a[2][1] - a[1][1]*a[2][0], -(a[0][0]*a[2][1] - a[0][1]*a[2][0]), a[0][0]*a[1][1] - a[0][1]*a[1][0]]
            ]
            inv = [[(cof[j][i] * inv_det) % 26 for i in range(size)] for j in range(size)]
    except ValueError:
        return "Error: Key is not invertible."

    blocks = [[ord(char) - ord('A') for char in message[i:i+size]] for i in range(0, len(message), size)]
    decrypted_matrix = []
    for block in blocks:
        decrypted = []
        for i in range(size):
            val = sum(block[j] * inv[i][j] for j in range(size)) % 26
            decrypted.append(val)
        decrypted_matrix.extend(decrypted)
    return ''.join(chr(c + ord('A')) for c in decrypted_matrix)

def upload_file_hill(message_entry):
    filename = filedialog.askopenfilename(initialdir="/", title="Select file",
                                          filetypes=(("Text files", ".txt"), ("All files", ".*")))
    if filename:
        with open(filename, "r") as file:
            content = file.read()
            message_entry.delete(0, customtkinter.END)
            message_entry.insert(0, content)


#Caesar cipher///////////////////////////
def open_caesar_scene():
    clear_frame()

    # Title
    title_label = customtkinter.CTkLabel(
        master=frame,
        text="CAESAR CIPHER",
        font=("Roboto", 28, "bold"),
        text_color="#4CC9F0"
    )
    title_label.grid(row=0, column=0, columnspan=2, pady=(30, 10))

    # Message Label + Entry
    message_label = create_label(frame, "Message:", 14)
    message_label.grid(row=1, column=0, sticky="e", padx=10, pady=10)

    message_entry = create_entry(frame)
    message_entry.grid(row=1, column=1, padx=10, pady=10)

    # Key Label + Entry
    key_label = create_label(frame, "Key (single letter):", 14)
    key_label.grid(row=2, column=0, sticky="e", padx=10, pady=10)

    key_entry = create_entry(frame)
    key_entry.grid(row=2, column=1, padx=10, pady=10)

    # Result Label + Entry
    result_label = create_label(frame, "Result:", 14)
    result_label.grid(row=3, column=0, sticky="e", padx=10, pady=10)

    result_entry = create_entry(frame)
    result_entry.grid(row=3, column=1, padx=10, pady=10)

    # Encrypt & Decrypt Buttons
    button_frame = customtkinter.CTkFrame(master=frame, fg_color="transparent")
    button_frame.grid(row=4, column=0, columnspan=2, pady=20)

    encrypt_button = create_action_button(
        master=button_frame,
        text="Encrypt",
        command=lambda: caesar_operation("encrypt", message_entry.get(), key_entry.get(), result_entry),
        color="#7209B7"
    )
    encrypt_button.pack(side="left", padx=10)

    decrypt_button = create_action_button(
        master=button_frame,
        text="Decrypt",
        command=lambda: caesar_operation("decrypt", message_entry.get(), key_entry.get(), result_entry),
        color="#3A0CA3"
    )
    decrypt_button.pack(side="left", padx=10)

    # Upload & Download Buttons
    upload_button = create_action_button(
        master=frame,
        text="Upload File",
        command=lambda: upload_file_caesar(message_entry),
        color="#4895EF"
    )
    upload_button.grid(row=5, column=0, columnspan=2, pady=10)

    download_button = create_action_button(
        master=frame,
        text="Download Result",
        command=lambda: download_file(result_entry.get()),
        color="#4CC9F0"
    )
    download_button.grid(row=6, column=0, columnspan=2, pady=10)

    # Home Button
    home_button = create_nav_button(
        master=frame,
        text="Back to Home",
        command=open_home_scene,
        color="#F72585"
    )
    home_button.grid(row=7, column=0, columnspan=2, pady=20)


def caesar_operation(operation, message, key, result_entry):
    # Clear previous result
    result_entry.delete(0, customtkinter.END)
    
    # Validate inputs
    if not message:
        result_entry.insert(0, "Error: Message cannot be empty")
        return
    
    if not key:
        result_entry.insert(0, "Error: Key cannot be empty")
        return
    
    # Validate key (must be single alphabetic letter only)
    if len(key) != 1:
        result_entry.insert(0, "Error: Key must be exactly one character")
        return
    
    if not key.isalpha():
        result_entry.insert(0, "Error: Key must be a letter (A-Z or a-z)")
        return
    
    # Validate message (letters and spaces only - no numbers or symbols)
    if any(char.isdigit() for char in message):
        result_entry.insert(0, "Error: Message cannot contain numbers")
        return
    
    if not all(char.isalpha() or char.isspace() for char in message):
        result_entry.insert(0, "Error: Message can only contain letters (A-Z, a-z) and spaces")
        return
    
    # Perform the operation
    if operation == "encrypt":
        result = encrypt_caesar(message, key)
    else:
        result = decrypt_caesar(message, key)
    
    result_entry.insert(0, result)

def encrypt_caesar(message, key):
    try:
        key = key.upper()
        key_shift = ord(key) - ord('A')
        result = ''
        for char in message:
            if char.isalpha():
                shifted = ord(char) + key_shift
                if char.isupper():
                    if shifted > ord('Z'):
                        shifted -= 26
                    elif shifted < ord('A'):
                        shifted += 26
                elif char.islower():
                    if shifted > ord('z'):
                        shifted -= 26
                    elif shifted < ord('a'):
                        shifted += 26
                result += chr(shifted)
            else:
                result += char
        return result
    except Exception as e:
        return f"Encryption Error: {str(e)}"

def decrypt_caesar(ciphertext, key):
    try:
        key = key.upper()
        key_shift = ord('A') - ord(key)
        result = ''
        for char in ciphertext:
            if char.isalpha():
                shifted = ord(char) + key_shift
                if char.isupper():
                    if shifted > ord('Z'):
                        shifted -= 26
                    elif shifted < ord('A'):
                        shifted += 26
                elif char.islower():
                    if shifted > ord('z'):
                        shifted -= 26
                    elif shifted < ord('a'):
                        shifted += 26
                result += chr(shifted)
            else:
                result += char
        return result
    except Exception as e:
        return f"Decryption Error: {str(e)}"

def upload_file_caesar(message_entry):
    try:
        filename = filedialog.askopenfilename(initialdir="/", title="Select file", filetypes=(("Text files", ".txt"), ("All files", ".*")))
        if filename:
            with open(filename, "r", encoding='utf-8') as file:
                content = file.read()
                if not content:
                    messagebox.showwarning("Warning", "The selected file is empty")
                    return
                message_entry.delete(0, customtkinter.END)
                message_entry.insert(0, content)
    except UnicodeDecodeError:
            messagebox.showerror("Error", "Could not read file - invalid encoding")
    except Exception as e:
            messagebox.showerror("Error", f"Failed to open file: {str(e)}")

def download_file(result_content):
    if not result_content:
            messagebox.showwarning("Warning", "No content to save")
            return
    
    try:
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=(("Text files", ".txt"), ("All files", ".*")))
        if filename:
            with open(filename, "w", encoding='utf-8') as file:
                file.write(result_content)
            messagebox.showinfo("Success", "File saved successfully")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save file: {str(e)}")


#Transposition cipher///////////////////////////
def update_result(entry, result):
    entry.delete(0, 'end') 
    entry.insert(0, result) 

def open_transposition_scene():
    clear_frame()

    # Title
    title_label = customtkinter.CTkLabel(
        master=frame,
        text="TRANSPOSITION CIPHER",
        font=("Roboto", 28, "bold"),
        text_color="#4CC9F0"
    )
    title_label.grid(row=0, column=0, columnspan=2, pady=(30, 10))

    # Message
    message_label = create_label(frame, "Message:", 14)
    message_label.grid(row=1, column=0, sticky="e", padx=10, pady=10)

    message_entry = create_entry(frame)
    message_entry.grid(row=1, column=1, padx=10, pady=10)

    # Key
    key_label = create_label(frame, "Key (letters):", 14)
    key_label.grid(row=2, column=0, sticky="e", padx=10, pady=10)

    key_entry = create_entry(frame)
    key_entry.grid(row=2, column=1, padx=10, pady=10)

    # Result
    result_label = create_label(frame, "Result:", 14)
    result_label.grid(row=3, column=0, sticky="e", padx=10, pady=10)

    result_entry = create_entry(frame)
    result_entry.grid(row=3, column=1, padx=10, pady=10)

    # Encrypt & Decrypt Buttons
    button_frame = customtkinter.CTkFrame(master=frame, fg_color="transparent")
    button_frame.grid(row=4, column=0, columnspan=2, pady=20)

    encrypt_button = create_action_button(
        master=button_frame,
        text="Encrypt",
        command=lambda: update_result(result_entry, encrypt_transposition(message_entry.get(), key_entry.get())),
        color="#7209B7"
    )
    encrypt_button.pack(side="left", padx=10)

    # Decrypt Button with update_result
    decrypt_button = create_action_button(
        master=button_frame,
        text="Decrypt",
        command=lambda: update_result(result_entry, decrypt_transposition(message_entry.get(), key_entry.get())),
        color="#3A0CA3"
    )
    decrypt_button.pack(side="left", padx=10)


    # Upload Button
    upload_button = create_action_button(
        master=frame,
        text="Upload File",
        command=lambda: upload_file(message_entry),
        color="#4895EF"
    )
    upload_button.grid(row=5, column=0, columnspan=2, pady=10)

    # Download Button
    download_button = create_action_button(
        master=frame,
        text="Download Result",
        command=lambda: download_file(result_entry.get()),
        color="#4CC9F0"
    )
    download_button.grid(row=6, column=0, columnspan=2, pady=10)

    # Home Button
    home_button = create_nav_button(
        master=frame,
        text="Back to Home",
        command=open_home_scene,
        color="#F72585"
    )
    home_button.grid(row=7, column=0, columnspan=2, pady=20)
    
def validate_inputs(message, key):
    if not message.strip():
        return "Error: Message cannot be empty."
    if not key.strip():
        return "Error: Key cannot be empty."
    if not message.replace(" ", "").isalpha():
        return "Error: Message must contain only letters (no numbers or symbols)."
    if not key.isalpha():
        return "Error: Key must contain only letters (no numbers or symbols)."
    if len(key) not in [4, 9]:
        return "Error: Key length must be exactly 4 or 9 characters."
    return None  # Valid input

def convert_key_to_numbers(key):
    key = key.upper()
    if not key.isalpha():
        return None
    return [ord(char) for char in key]

def encrypt_transposition(message, key):
    validation_error = validate_inputs(message, key)
    if validation_error:
        return validation_error

    numeric_key = convert_key_to_numbers(key)
    col_count = len(numeric_key)
    rows = (len(message) + col_count - 1) // col_count
    padded_length = rows * col_count
    message += ' ' * (padded_length - len(message))

    grid = ['' for _ in range(col_count)]
    for i, char in enumerate(message):
        col = i % col_count
        grid[col] += char

    key_order = sorted(list(enumerate(numeric_key)), key=lambda x: x[1])
    result = ''.join(grid[i] for i, _ in key_order)
    return result

def decrypt_transposition(ciphertext, key):
    validation_error = validate_inputs(ciphertext, key)
    if validation_error:
        return validation_error

    numeric_key = convert_key_to_numbers(key)
    col_count = len(numeric_key)
    rows = (len(ciphertext) + col_count - 1) // col_count
    short_cols = col_count * rows - len(ciphertext)

    key_order = sorted(list(enumerate(numeric_key)), key=lambda x: x[1])
    col_lengths = [rows - 1 if i < short_cols else rows for i in range(col_count)]

    cols = [''] * col_count
    index = 0
    for (i, _), length in zip(key_order, col_lengths):
        cols[i] = ciphertext[index:index + length]
        index += length

    result = ''
    for row in range(rows):
        for col in range(col_count):
            if row < len(cols[col]):
                result += cols[col][row]
    return result.strip()

def upload_file(message_entry):
    filename = filedialog.askopenfilename(initialdir="/", title="Select file",
                                          filetypes=(("Text files", ".txt"), ("All files", ".*")))
    if filename:
        with open(filename, "r") as file:
            content = file.read()
            message_entry.delete(0, customtkinter.END)
            message_entry.insert(0, content)

def download_file(result_content):
    filename = filedialog.asksaveasfilename(defaultextension=".txt",
                                            filetypes=(("Text files", ".txt"), ("All files", ".*")))
    if filename:
        with open(filename, "w") as file:
            file.write(result_content)

def upload_file_transposition(message_entry, result_entry, key_enytry=None):
    filename = filedialog.askopenfilename(initialdir="/", title="Select file", filetypes=(("Text files", ".txt"), ("All files", ".*")))
    if filename:
        with open(filename, "r") as file:
            content = file.read()
            message_entry.delete(0, customtkinter.END)
            message_entry.insert(0, content)
            encrypted_or_decrypted = encrypt_transposition(content, key_enytry.get())  # Assuming the key is already entered
            result_entry.delete(0, customtkinter.END)
            result_entry.insert(0, encrypted_or_decrypted)
    filename = filedialog.askopenfilename(initialdir="/", title="Select file", filetypes=(("Text files", ".txt"), ("All files", ".*")))
    if filename:
        with open(filename, "r") as file:
            content = file.read()
            message_entry.delete(0, customtkinter.END)
            message_entry.insert(0, content)
            encrypted_or_decrypted = encrypt_transposition(content, key_enytry.get())  # Assuming the key is already entered
            result_entry.delete(0, customtkinter.END)
            result_entry.insert(0, encrypted_or_decrypted)

#substitution Cipher ///////////////////////////
def update_result(entry, result):
    entry.delete(0, 'end') 
    entry.insert(0, result) 

def open_substitution_scene():
    clear_frame()

    # Title
    title_label = customtkinter.CTkLabel(
        master=frame,
        text="SUBSTITUTION CIPHER",
        font=("Roboto", 28, "bold"),
        text_color="#4CC9F0"
    )
    title_label.grid(row=0, column=0, columnspan=2, pady=(30, 10))

    # Message
    message_label = create_label(frame, "Message:", 14)
    message_label.grid(row=1, column=0, sticky="e", padx=10, pady=10)

    message_entry = create_entry(frame)
    message_entry.grid(row=1, column=1, padx=10, pady=10)

    # Key
    key_label = create_label(frame, "Key (26 letters):", 14)
    key_label.grid(row=2, column=0, sticky="e", padx=10, pady=10)

    key_entry = create_entry(frame)
    key_entry.grid(row=2, column=1, padx=10, pady=10)

    # Result
    result_label = create_label(frame, "Result:", 14)
    result_label.grid(row=3, column=0, sticky="e", padx=10, pady=10)

    result_entry = create_entry(frame)
    result_entry.grid(row=3, column=1, padx=10, pady=10)

    # Encrypt & Decrypt Buttons
    button_frame = customtkinter.CTkFrame(master=frame, fg_color="transparent")
    button_frame.grid(row=4, column=0, columnspan=2, pady=20)


    encrypt_button = create_action_button(
        master=button_frame,
        text="Encrypt",
        command=lambda: update_result(result_entry, encrypt_substitution(message_entry.get(), key_entry.get())),
        color="#7209B7"
    )
    encrypt_button.pack(side="left", padx=10)

    # Decrypt Button with update_result
    decrypt_button = create_action_button(
        master=button_frame,
        text="Decrypt",
        command=lambda: update_result(result_entry, decrypt_substitution(message_entry.get(), key_entry.get())),
        color="#3A0CA3"
    )
    decrypt_button.pack(side="left", padx=10)

    # Upload Button
    upload_button = create_action_button(
        master=frame,
        text="Upload File",
        command=lambda: upload_file_substitution(message_entry, result_entry),
        color="#4895EF"
    )
    upload_button.grid(row=5, column=0, columnspan=2, pady=10)

    # Download Button
    download_button = create_action_button(
        master=frame,
        text="Download Result",
        command=lambda: download_file(result_entry.get()),
        color="#4CC9F0"
    )
    download_button.grid(row=6, column=0, columnspan=2, pady=10)

    # Home Button
    home_button = create_nav_button(
        master=frame,
        text="Back to Home",
        command=open_home_scene,
        color="#F72585"
    )
    home_button.grid(row=7, column=0, columnspan=2, pady=20)

def validate_substitution_input(message, key):
    if not message.strip() or not key.strip():
        return "Error: Message and key must not be empty."

    if any(char.isdigit() for char in message) or any(char.isdigit() for char in key):
        return "Error: Message and key must not contain numbers."

    if not key.isalpha() or not message.replace(" ", "").isalpha():
        return "Error: Message and key must contain letters only (no symbols)."

    key = key.upper()
    if len(key) != 26 or len(set(key)) != 26:
        return "Error: Key must be 26 distinct letters of the alphabet."

    return "OK"

def encrypt_substitution(message, key):
    # Validation
    validation_result = validate_substitution_input(message, key)
    if validation_result != "OK":
        return validation_result

    # Substitution logic
    key = key.upper()
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    encryption_map = {alphabet[i]: key[i] for i in range(26)}

    result = ''
    for char in message:
        if char.isalpha():
            result += encryption_map[char.upper()] if char.isupper() else encryption_map[char.upper()].lower()
        else:
            result += char  # Keep spaces/symbols
    return result

def decrypt_substitution(message, key):
    # Validation
    validation_result = validate_substitution_input(message, key)
    if validation_result != "OK":
        return validation_result

    # Substitution logic
    key = key.upper()
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    decryption_map = {key[i]: alphabet[i] for i in range(26)}

    result = ''
    for char in message:
        if char.isalpha():
            result += decryption_map[char.upper()] if char.isupper() else decryption_map[char.upper()].lower()
        else:
            result += char  # Keep spaces/symbols
    return result

def upload_file_substitution(message_entry, result_entry):
    filename = filedialog.askopenfilename(
        initialdir="/",
        title="Select file",
        filetypes=(("Text files", ".txt"), ("All files", ".*"))
    )
    if filename:
        with open(filename, "r") as file:
            content = file.read()
            message_entry.delete(0, customtkinter.END)
            message_entry.insert(0, content)
            
def download_file(result_content):
    filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=(("Text files", ".txt"), ("All files", ".*")))
    if filename:
        with open(filename, "w") as file:
            file.write(result_content)

#Rot13 Cipher ///////////////////////////

def open_rot13_scene():
    clear_frame()

    # Title
    title_label = customtkinter.CTkLabel(
        master=frame,
        text="ROT13 CIPHER",
        font=("Roboto", 28, "bold"),
        text_color="#4CC9F0"
    )
    title_label.grid(row=0, column=0, columnspan=2, pady=(30, 10))

    # Message input
    message_label = create_label(frame, "Message:", 14)
    message_label.grid(row=1, column=0, sticky="e", padx=10, pady=10)

    message_entry = create_entry(frame)
    message_entry.grid(row=1, column=1, padx=10, pady=10)

    # Result output
    result_label = create_label(frame, "Result:", 14)
    result_label.grid(row=2, column=0, sticky="e", padx=10, pady=10)

    result_entry = create_entry(frame)
    result_entry.grid(row=2, column=1, padx=10, pady=10)

    # Buttons (Encrypt/Decrypt)
    button_frame = customtkinter.CTkFrame(master=frame, fg_color="transparent")
    button_frame.grid(row=3, column=0, columnspan=2, pady=20)

    encrypt_button = create_action_button(
        master=button_frame,
        text="Encrypt",
        command=lambda: rot13_operation("encrypt", message_entry.get(), result_entry),
        color="#7209B7"
    )
    encrypt_button.pack(side="left", padx=10)

    decrypt_button = create_action_button(
        master=button_frame,
        text="Decrypt",
        command=lambda: rot13_operation("decrypt", message_entry.get(), result_entry),
        color="#3A0CA3"
    )
    decrypt_button.pack(side="left", padx=10)

    # Upload
    upload_button = create_action_button(
        master=frame,
        text="Upload File",
        command=lambda: upload_file_rot13(message_entry, result_entry),
        color="#4895EF"
    )
    upload_button.grid(row=4, column=0, columnspan=2, pady=10)

    # Download
    download_button = create_action_button(
        master=frame,
        text="Download Result",
        command=lambda: download_file(result_entry.get()),
        color="#4CC9F0"
    )
    download_button.grid(row=5, column=0, columnspan=2, pady=10)

    # Home
    home_button = create_nav_button(
        master=frame,
        text="Back to Home",
        command=open_home_scene,
        color="#F72585"
    )
    home_button.grid(row=6, column=0, columnspan=2, pady=20)

def rot13_operation(operation, message, result_entry):
    result_entry.delete(0, customtkinter.END)

    # Validate message
    if not message:
        result_entry.insert(0, "Error: Message cannot be empty")
        return
    
    if any(char.isdigit() for char in message):
        result_entry.insert(0, "Error: Message cannot contain numbers")
        return
    
    if not all(char.isalpha() or char.isspace() for char in message):
        result_entry.insert(0, "Error: Message can only contain letters (A-Z, a-z) and spaces")
        return

    # Perform the operation
    result = encrypt_rot13(message)
    result_entry.insert(0, result)

def encrypt_rot13(message):
    return ''.join([
        chr(((ord(char) - ord('a' if char.islower() else 'A') + 13) % 26) + ord('a' if char.islower() else 'A'))
        if char.isalpha() else char for char in message
    ])

def decrypt_rot13(message):
    return encrypt_rot13(message)

def upload_file_rot13(message_entry, result_entry):
    filename = filedialog.askopenfilename(
        initialdir="/",
        title="Select file",
        filetypes=(("Text files", ".txt"), ("All files", ".*"))
    )
    if filename:
        with open(filename, "r") as file:
            content = file.read()
            message_entry.delete(0, customtkinter.END)
            message_entry.insert(0, content)

def download_file(result_content):
    filename = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=(("Text files", ".txt"), ("All files", ".*"))
    )
    if filename:
        with open(filename, "w") as file:
            file.write(result_content)

frame = customtkinter.CTkFrame(master=root)
frame.pack(pady=20, padx=60, fill="both", expand=True)

#Affine Cipher ///////////////////////////

def open_affine_scene(result=None):
    clear_frame()

    # Title
    title_label = customtkinter.CTkLabel(
        master=frame,
        text="AFFINE CIPHER",
        font=("Roboto", 28, "bold"),
        text_color="#4CC9F0"
    )
    title_label.grid(row=0, column=0, columnspan=2, pady=(30, 10))

    # Message Input
    message_label = create_label(frame, "Message:", 14)
    message_label.grid(row=1, column=0, sticky="e", padx=10, pady=10)

    message_entry = create_entry(frame)
    message_entry.grid(row=1, column=1, padx=10, pady=10)

    # Result Output
    result_label = create_label(frame, "Result:", 14)
    result_label.grid(row=2, column=0, sticky="e", padx=10, pady=10)

    result_entry = create_entry(frame)
    result_entry.grid(row=2, column=1, padx=10, pady=10)

    # Key A Input
    key_label_a = create_label(frame, "Key A (letter):", 14)
    key_label_a.grid(row=3, column=0, sticky="e", padx=10, pady=10)

    key_entry_a = create_entry(frame)
    key_entry_a.grid(row=3, column=1, padx=10, pady=10)

    # Key B Input
    key_label_b = create_label(frame, "Key B (letter):", 14)
    key_label_b.grid(row=4, column=0, sticky="e", padx=10, pady=10)

    key_entry_b = create_entry(frame)
    key_entry_b.grid(row=4, column=1, padx=10, pady=10)

    # Button Frame
    button_frame = customtkinter.CTkFrame(master=frame, fg_color="transparent")
    button_frame.grid(row=5, column=0, columnspan=2, pady=20)

    encrypt_button = create_action_button(
        master=button_frame,
        text="Encrypt",
        command=lambda: result_entry.insert(0, encrypt_affine(message_entry.get(), key_entry_a.get(), key_entry_b.get())),
        color="#CD5C5C"
    )
    encrypt_button.pack(side="left", padx=10)

    decrypt_button = create_action_button(
        master=button_frame,
        text="Decrypt",
        command=lambda: result_entry.insert(0, decrypt_affine(message_entry.get(), key_entry_a.get(), key_entry_b.get())),
        color="#CD5C5C"
    )
    decrypt_button.pack(side="left", padx=10)

    # Upload Button
    upload_button = create_action_button(
        master=frame,
        text="Upload File",
        command=lambda: upload_file_affine(message_entry, result_entry, key_entry_a, key_entry_b),
        color="#FA8072"
    )
    upload_button.grid(row=6, column=0, columnspan=2, pady=10)

    # Download Button
    download_button = create_action_button(
        master=frame,
        text="Download Result",
        command=lambda: download_file(result_entry.get()),
        color="#008080"
    )
    download_button.grid(row=7, column=0, columnspan=2, pady=10)

    # Home Button
    home_button = create_nav_button(
        master=frame,
        text="Back to Home",
        command=open_home_scene,
        color="#F94144"
    )
    home_button.grid(row=8, column=0, columnspan=2, pady=20)

def validate_affine_input(message, key_a, key_b):
 
    if not message.strip():
        return "Error: Message must not be empty."

    if any(char.isdigit() for char in message):
        return "Error: Message must not contain numbers."

   
    if any(not char.isalpha() and char != ' ' for char in message):
        return "Error: Message must not contain symbols."


    if not message.replace(" ", "").isalpha():
        return "Error: Message must contain only letters and spaces."

   
    if not key_a.strip() or not key_b.strip():
        return "Error: Key A and Key B must not be empty."

  
    if any(char.isdigit() or not char.isalpha() for char in key_a + key_b):
        return "Error: Key A and Key B must contain only letters."

  
    if gcd(ord(key_a.upper()) - ord('A'), 26) != 1:
        return "Error: Key A must be coprime with 26 (i.e., gcd(a, 26) = 1)."

    return "OK"

def encrypt_affine(message, key_a, key_b):
    
    validation_result = validate_affine_input(message, key_a, key_b)
    if validation_result != "OK":
        return validation_result

    key_a_num = ord(key_a.upper()) - ord('A')
    key_b_num = ord(key_b.upper()) - ord('A')

    result = ''
    for char in message:
        if char.isalpha():
            if char.islower():
                result += chr(((key_a_num * (ord(char) - ord('a')) + key_b_num) % 26) + ord('a'))
            else:
                result += chr(((key_a_num * (ord(char) - ord('A')) + key_b_num) % 26) + ord('A'))
        else:
            result += char
    return result

def decrypt_affine(ciphertext, key_a, key_b):
   
    validation_result = validate_affine_input(ciphertext, key_a, key_b)
    if validation_result != "OK":
        return validation_result

    key_a_num = ord(key_a.upper()) - ord('A')
    key_b_num = ord(key_b.upper()) - ord('A')

    key_a_inv = mod_inverse(key_a_num, 26)
    if key_a_inv is None:
        return "Error: Key A has no modular inverse (i.e., a is not coprime with 26)."

    result = ''
    for char in ciphertext:
        if char.isalpha():
            if char.islower():
                result += chr(((key_a_inv * (ord(char) - ord('a') - key_b_num)) % 26) + ord('a'))
            else:
                result += chr(((key_a_inv * (ord(char) - ord('A') - key_b_num)) % 26) + ord('A'))
        else:
            result += char
    return result

def upload_file_affine(message_entry, result_entry, key_entry_a, key_entry_b):
    filename = filedialog.askopenfilename(initialdir="/", title="Select file",
                                          filetypes=(("Text files", ".txt"), ("All files", ".*")))
    if filename:
        with open(filename, "r") as file:
            content = file.read()
            message_entry.delete(0, customtkinter.END)
            message_entry.insert(0, content)
            result_entry.delete(0, customtkinter.END)

def download_file(result_content):
    filename = filedialog.asksaveasfilename(defaultextension=".txt",
                                            filetypes=(("Text files", ".txt"), ("All files", ".*")))
    if filename:
        with open(filename, "w") as file:
            file.write(result_content)

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

#-------Rial---------------------------------------

def open_railfence_scene():
    clear_frame()

    # Title
    title_label = customtkinter.CTkLabel(
        master=frame,
        text="RAIL FENCE CIPHER",
        font=("Roboto", 28, "bold"),
        text_color="#4CC9F0"
    )
    title_label.grid(row=0, column=0, columnspan=2, pady=(30, 10))

    # Rails input
    rails_label = create_label(frame, "Number of Rails:", 14)
    rails_label.grid(row=1, column=0, sticky="e", padx=10, pady=10)

    rails_entry = customtkinter.CTkEntry(
        master=frame,
        font=("Roboto", 12),
        width=100
    )
    rails_entry.grid(row=1, column=1, sticky="w", padx=10, pady=10)
    rails_entry.insert(0, "3")  # Default value

    # Message input
    message_label = create_label(frame, "Message:", 14)
    message_label.grid(row=2, column=0, sticky="e", padx=10, pady=10)

    message_entry = create_entry(frame)
    message_entry.grid(row=2, column=1, padx=10, pady=10)

    # Result output
    result_label = create_label(frame, "Result:", 14)
    result_label.grid(row=3, column=0, sticky="e", padx=10, pady=10)

    result_entry = create_entry(frame)
    result_entry.grid(row=3, column=1, padx=10, pady=10)

    # Buttons (Encrypt/Decrypt)
    button_frame = customtkinter.CTkFrame(master=frame, fg_color="transparent")
    button_frame.grid(row=4, column=0, columnspan=2, pady=20)

    encrypt_button = create_action_button(
        master=button_frame,
        text="Encrypt",
        command=lambda: railfence_operation("encrypt", message_entry.get(), rails_entry.get(), result_entry),
        color="#7209B7"
    )
    encrypt_button.pack(side="left", padx=10)

    decrypt_button = create_action_button(
        master=button_frame,
        text="Decrypt",
        command=lambda: railfence_operation("decrypt", message_entry.get(), rails_entry.get(), result_entry),
        color="#3A0CA3"
    )
    decrypt_button.pack(side="left", padx=10)

    # Upload
    upload_button = create_action_button(
        master=frame,
        text="Upload File",
        command=lambda: upload_file_railfence(message_entry, result_entry),
        color="#4895EF"
    )
    upload_button.grid(row=5, column=0, columnspan=2, pady=10)

    # Download
    download_button = create_action_button(
        master=frame,
        text="Download Result",
        command=lambda: download_file(result_entry.get()),
        color="#4CC9F0"
    )
    download_button.grid(row=6, column=0, columnspan=2, pady=10)

    # Home
    home_button = create_nav_button(
        master=frame,
        text="Back to Home",
        command=open_home_scene,
        color="#F72585"
    )
    home_button.grid(row=7, column=0, columnspan=2, pady=20)

def railfence_operation(operation, message, rails, result_entry):
    result_entry.delete(0, customtkinter.END)

    # Validate inputs
    if not message:
        result_entry.insert(0, "Error: Message cannot be empty")
        return
    
    if not rails.isdigit() or int(rails) < 2:
        result_entry.insert(0, "Error: Rails must be integer ≥ 2")
        return
    
    rails = int(rails)
    
    if not all(char.isalpha() or char.isspace() for char in message):
        result_entry.insert(0, "Error: Message can only contain letters and spaces")
        return

    # Perform the operation
    try:
        if operation == "encrypt":
            result = encryptRailFence(message.upper(), rails)
        else:
            result = decryptRailFence(message.upper(), rails)
        result_entry.insert(0, result)
    except Exception as e:
        result_entry.insert(0, f"Error: {str(e)}")


def encryptRailFence(text, key):
    """Encrypt text using Rail Fence Cipher"""
    rail = [['\n' for _ in range(len(text))] for _ in range(key)]
    
    dir_down = False
    row, col = 0, 0
    
    for i in range(len(text)):
        if row == 0 or row == key - 1:
            dir_down = not dir_down
        
        rail[row][col] = text[i]
        col += 1
        
        if dir_down:
            row += 1
        else:
            row -= 1
    
    result = []
    for i in range(key):
        for j in range(len(text)):
            if rail[i][j] != '\n':
                result.append(rail[i][j])
    return ''.join(result)


def decryptRailFence(cipher, key):
    """Decrypt Rail Fence Cipher"""
    rail = [['\n' for _ in range(len(cipher))] for _ in range(key)]
    
    dir_down = None
    row, col = 0, 0
    
    # Mark the positions with '*'
    for i in range(len(cipher)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        
        rail[row][col] = '*'
        col += 1
        
        if dir_down:
            row += 1
        else:
            row -= 1
    
    # Fill the rail matrix with cipher characters
    index = 0
    for i in range(key):
        for j in range(len(cipher)):
            if rail[i][j] == '*' and index < len(cipher):
                rail[i][j] = cipher[index]
                index += 1
    
    # Read the matrix in zig-zag manner
    result = []
    row, col = 0, 0
    for i in range(len(cipher)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        
        if rail[row][col] != '*':
            result.append(rail[row][col])
            col += 1
        
        if dir_down:
            row += 1
        else:
            row -= 1
    
    return ''.join(result)

def upload_file_railfence(message_entry, result_entry):
    filename = filedialog.askopenfilename(
        initialdir="/",
        title="Select file",
        filetypes=(("Text files", ".txt"), ("All files", ".*"))
    )
    if filename:
        with open(filename, "r") as file:
            content = file.read()
            message_entry.delete(0, customtkinter.END)
            message_entry.insert(0, content)

#---------------PLAY FAIR----------------------------------------------------
def open_playfair_scene():
    clear_frame()

    # Title
    title_label = customtkinter.CTkLabel(
        master=frame,
        text="PLAYFAIR CIPHER",
        font=("Roboto", 28, "bold"),
        text_color="#4CC9F0"
    )
    title_label.grid(row=0, column=0, columnspan=2, pady=(30, 10))



    # Message input
    message_label = create_label(frame, "Message:", 14)
    message_label.grid(row=2, column=0, sticky="e", padx=10, pady=10)

    message_entry = create_entry(frame)
    message_entry.grid(row=2, column=1, padx=10, pady=10)

    # Keyword input
    keyword_label = create_label(frame, "Key(letter):", 14)
    keyword_label.grid(row=1, column=0, sticky="e", padx=10, pady=10)

    keyword_entry = create_entry(frame)
    keyword_entry.grid(row=1, column=1, padx=10, pady=10)

    # Result output
    result_label = create_label(frame, "Result:", 14)
    result_label.grid(row=3, column=0, sticky="e", padx=10, pady=10)

    result_entry = create_entry(frame)
    result_entry.grid(row=3, column=1, padx=10, pady=10)

    # Buttons (Encrypt/Decrypt)
    button_frame = customtkinter.CTkFrame(master=frame, fg_color="transparent")
    button_frame.grid(row=4, column=0, columnspan=2, pady=20)

    encrypt_button = create_action_button(
        master=button_frame,
        text="Encrypt",
        command=lambda: playfair_operation("encrypt", keyword_entry.get(), message_entry.get(), result_entry),
        color="#7209B7"
    )
    encrypt_button.pack(side="left", padx=10)

    decrypt_button = create_action_button(
        master=button_frame,
        text="Decrypt",
        command=lambda: playfair_operation("decrypt", keyword_entry.get(), message_entry.get(), result_entry),
        color="#3A0CA3"
    )
    decrypt_button.pack(side="left", padx=10)

    # Upload
    upload_button = create_action_button(
        master=frame,
        text="Upload File",
        command=lambda: upload_file_playfair(message_entry, result_entry),
        color="#4895EF"
    )
    upload_button.grid(row=5, column=0, columnspan=2, pady=10)

    # Download
    download_button = create_action_button(
        master=frame,
        text="Download Result",
        command=lambda: download_file(result_entry.get()),
        color="#4CC9F0"
    )
    download_button.grid(row=6, column=0, columnspan=2, pady=10)

    # Home
    home_button = create_nav_button(
        master=frame,
        text="Back to Home",
        command=open_home_scene,
        color="#F72585"
    )
    home_button.grid(row=7, column=0, columnspan=2, pady=20)


def playfair_operation(operation, keyword, message, result_entry):
    result_entry.delete(0, customtkinter.END)

    # Validate inputs
    if not keyword:
        result_entry.insert(0, "Error: Keyword cannot be empty")
        return
    
    if not message:
        result_entry.insert(0, "Error: Message cannot be empty")
        return
    
    if not keyword.isalpha():
        result_entry.insert(0, "Error: Keyword can only contain letters")
        return
    
    if not all(char.isalpha() or char.isspace() for char in message):
        result_entry.insert(0, "Error: Message can only contain letters and spaces")
        return

    try:
        if operation == "encrypt":
            result = encryptByPlayfairCipher(message, keyword)
        else:
            result = decryptByPlayfairCipher(message, keyword)
        
        result_entry.insert(0, result)
    except Exception as e:
        result_entry.insert(0, f"Error: {str(e)}")


def toLowerCase(plain):
    """Convert string to lowercase"""
    return plain.lower()


def removeSpaces(plain):
    """Remove all spaces from string"""
    return ''.join([c for c in plain if c != ' '])


def generateKeyTable(key, keyT):
    """Generate the 5x5 key square"""
    key = removeSpaces(toLowerCase(key))
    keyT.clear()
    
    # Initialize 5x5 matrix with zeros
    for i in range(5):
        keyT.append([0]*5)
    
    # Track which letters we've used (0=unused, 1=j, 2=used)
    hashMap = [0]*26
    
    # Mark letters in key as used (treat j as i)
    for c in key:
        if c == 'j':
            hashMap[ord('i') - 97] = 2
        else:
            hashMap[ord(c) - 97] = 2
    
    # Mark j as used (we'll treat it as i)
    hashMap[ord('j') - 97] = 1
    
    # Fill the key table
    i, j = 0, 0
    
    # First with key letters
    for c in key:
        if c == 'j':
            c = 'i'
        if hashMap[ord(c) - 97] == 2:
            hashMap[ord(c) - 97] -= 1
            keyT[i][j] = c
            j += 1
            if j == 5:
                i += 1
                j = 0
    
    # Then with remaining alphabet letters
    for k in range(26):
        if hashMap[k] == 0:
            keyT[i][j] = chr(k + 97)
            j += 1
            if j == 5:
                i += 1
                j = 0


def search(keyT, a, b, arr):
    """Search for characters in key table and return positions"""
    if a == 'j':
        a = 'i'
    if b == 'j':
        b = 'i'
    
    for i in range(5):
        for j in range(5):
            if keyT[i][j] == a:
                arr[0], arr[1] = i, j
            elif keyT[i][j] == b:
                arr[2], arr[3] = i, j


def prepare(string):
    """Prepare the plaintext (make length even, handle doubles)"""
    string = removeSpaces(toLowerCase(string))
    
    # Replace j with i
    string = string.replace('j', 'i')
    
    # Insert x between double letters and pad with z if odd length
    i = 0
    while i < len(string) - 1:
        if string[i] == string[i+1]:
            string = string[:i+1] + 'x' + string[i+1:]
        i += 2
    
    if len(string) % 2 != 0:
        string += 'z'
    
    return string


def encrypt(string, keyT):
    """Perform the encryption using the key table"""
    n = len(string)
    arr = [0]*4
    result = list(string)
    
    for i in range(0, n, 2):
        search(keyT, result[i], result[i+1], arr)
        
        # Same row
        if arr[0] == arr[2]:
            result[i] = keyT[arr[0]][(arr[1] + 1) % 5]
            result[i+1] = keyT[arr[0]][(arr[3] + 1) % 5]
        # Same column
        elif arr[1] == arr[3]:
            result[i] = keyT[(arr[0] + 1) % 5][arr[1]]
            result[i+1] = keyT[(arr[2] + 1) % 5][arr[1]]
        # Rectangle rule
        else:
            result[i] = keyT[arr[0]][arr[3]]
            result[i+1] = keyT[arr[2]][arr[1]]
    
    return ''.join(result)


def decrypt(string, keyT):
    """Perform the decryption using the key table"""
    n = len(string)
    arr = [0]*4
    result = list(string)
    
    for i in range(0, n, 2):
        search(keyT, result[i], result[i+1], arr)
        
        # Same row
        if arr[0] == arr[2]:
            result[i] = keyT[arr[0]][(arr[1] - 1) % 5]
            result[i+1] = keyT[arr[0]][(arr[3] - 1) % 5]
        # Same column
        elif arr[1] == arr[3]:
            result[i] = keyT[(arr[0] - 1) % 5][arr[1]]
            result[i+1] = keyT[(arr[2] - 1) % 5][arr[1]]
        # Rectangle rule
        else:
            result[i] = keyT[arr[0]][arr[3]]
            result[i+1] = keyT[arr[2]][arr[1]]
    
    return ''.join(result)


def encryptByPlayfairCipher(string, key):
    """Encrypt using Playfair Cipher"""
    keyT = []
    generateKeyTable(key, keyT)
    string = prepare(string)
    return encrypt(string, keyT)


def decryptByPlayfairCipher(string, key):
    """Decrypt using Playfair Cipher"""
    keyT = []
    generateKeyTable(key, keyT)
    string = removeSpaces(toLowerCase(string))
    return decrypt(string, keyT)


def upload_file_playfair(message_entry, result_entry):
    filename = filedialog.askopenfilename(
        initialdir="/",
        title="Select file",
        filetypes=(("Text files", ".txt"), ("All files", ".*"))
    )
    if filename:
        with open(filename, "r") as file:
            content = file.read()
            message_entry.delete(0, customtkinter.END)
            message_entry.insert(0, content)


#--------SRA------------------------------------------------------

def open_rsa_scene():
    clear_frame()

    # Generate RSA keys when scene opens
    e, d, n = generateKeys()

    # Title
    title_label = customtkinter.CTkLabel(
        master=frame,
        text="RSA CIPHER",
        font=("Roboto", 28, "bold"),
        text_color="#4CC9F0"
    )
    title_label.grid(row=0, column=0, columnspan=2, pady=(30, 10))

    # Key display
    public_key_label = create_label(frame, "Public Key (e, n):", 14)
    public_key_label.grid(row=1, column=0, sticky="e", padx=10, pady=5)

    public_key_display = customtkinter.CTkTextbox(
        master=frame,
        font=("Roboto", 10),
        height=50,
        width=300,
        wrap="word"
    )
    public_key_display.grid(row=1, column=1, sticky="w", padx=10, pady=5)
    public_key_display.insert("1.0", f"e: {e}\nn: {n}")
    public_key_display.configure(state="disabled")

    private_key_label = create_label(frame, "Private Key (d, n):", 14)
    private_key_label.grid(row=2, column=0, sticky="e", padx=10, pady=5)

    private_key_display = customtkinter.CTkTextbox(
        master=frame,
        font=("Roboto", 10),
        height=50,
        width=300,
        wrap="word"
    )
    private_key_display.grid(row=2, column=1, sticky="w", padx=10, pady=5)
    private_key_display.insert("1.0", f"d: {d}\nn: {n}")
    private_key_display.configure(state="disabled")

    # Message input
    message_label = create_label(frame, "Message:", 14)
    message_label.grid(row=3, column=0, sticky="e", padx=10, pady=10)

    message_entry = create_entry(frame)
    message_entry.grid(row=3, column=1, padx=10, pady=10)

    # Result output
    result_label = create_label(frame, "Result:", 14)
    result_label.grid(row=4, column=0, sticky="e", padx=10, pady=10)

    result_display = customtkinter.CTkTextbox(
        master=frame,
        font=("Roboto", 12),
        height=100,
        width=300,
        wrap="word"
    )
    result_display.grid(row=4, column=1, padx=10, pady=10)

    # Buttons
    button_frame = customtkinter.CTkFrame(master=frame, fg_color="transparent")
    button_frame.grid(row=5, column=0, columnspan=2, pady=20)

    encrypt_button = create_action_button(
        button_frame, "Encrypt", 
        lambda: rsa_operation("encrypt", message_entry.get(), result_display, e, n),
        "#7209B7"
    )
    encrypt_button.pack(side="left", padx=10)

    decrypt_button = create_action_button(
        button_frame, "Decrypt",
        lambda: rsa_operation("decrypt", message_entry.get(), result_display, d, n),
        "#3A0CA3"
    )
    decrypt_button.pack(side="left", padx=10)

    # File operations
    file_frame = customtkinter.CTkFrame(master=frame, fg_color="transparent")
    file_frame.grid(row=6, column=0, columnspan=2, pady=10)

    upload_button = create_action_button(
        file_frame, "Upload File",
        lambda: upload_file(message_entry),
        "#4895EF"
    )
    upload_button.pack(side="left", padx=10)

    download_button = create_action_button(
        file_frame, "Download Result",
        lambda: download_file(result_display.get("1.0", "end-1c")),
        "#4CC9F0"
    )
    download_button.pack(side="left", padx=10)

    # Home button
    home_button = create_nav_button(
        frame, "Back to Home", open_home_scene, "#F72585"
    )
    home_button.grid(row=7, column=0, columnspan=2, pady=20)

import customtkinter
from tkinter import filedialog, messagebox

def open_rsa_scene():
    clear_frame()

    # Generate RSA keys when scene opens
    e, d, n = generateKeys()

    # Title
    title_label = customtkinter.CTkLabel(
        master=frame,
        text="RSA CIPHER",
        font=("Roboto", 28, "bold"),
        text_color="#4CC9F0"
    )
    title_label.grid(row=0, column=0, columnspan=2, pady=(30, 10))

    # Key display
    public_key_label = create_label(frame, "Public Key (e, n):", 14)
    public_key_label.grid(row=1, column=0, sticky="e", padx=10, pady=5)

    public_key_display = customtkinter.CTkTextbox(
        master=frame,
        font=("Roboto", 10),
        height=50,
        width=300,
        wrap="word"
    )
    public_key_display.grid(row=1, column=1, sticky="w", padx=10, pady=5)
    public_key_display.insert("1.0", f"e: {e}\nn: {n}")
    public_key_display.configure(state="disabled")

    private_key_label = create_label(frame, "Private Key (d, n):", 14)
    private_key_label.grid(row=2, column=0, sticky="e", padx=10, pady=5)

    private_key_display = customtkinter.CTkTextbox(
        master=frame,
        font=("Roboto", 10),
        height=50,
        width=300,
        wrap="word"
    )
    private_key_display.grid(row=2, column=1, sticky="w", padx=10, pady=5)
    private_key_display.insert("1.0", f"d: {d}\nn: {n}")
    private_key_display.configure(state="disabled")

    # Message input
    message_label = create_label(frame, "Message:", 14)
    message_label.grid(row=3, column=0, sticky="e", padx=10, pady=10)

    message_entry = create_entry(frame)
    message_entry.grid(row=3, column=1, padx=10, pady=10)

    # Result output
    result_label = create_label(frame, "Result:", 14)
    result_label.grid(row=4, column=0, sticky="e", padx=10, pady=10)

    result_display = customtkinter.CTkTextbox(
        master=frame,
        font=("Roboto", 12),
        height=100,
        width=300,
        wrap="word"
    )
    result_display.grid(row=4, column=1, padx=10, pady=10)

    # Buttons
    button_frame = customtkinter.CTkFrame(master=frame, fg_color="transparent")
    button_frame.grid(row=5, column=0, columnspan=2, pady=20)

    encrypt_button = create_action_button(
        button_frame, "Encrypt", 
        lambda: rsa_operation("encrypt", message_entry.get(), result_display, e, n),
        "#7209B7"
    )
    encrypt_button.pack(side="left", padx=10)

    decrypt_button = create_action_button(
        button_frame, "Decrypt",
        lambda: rsa_operation("decrypt", message_entry.get(), result_display, d, n),
        "#3A0CA3"
    )
    decrypt_button.pack(side="left", padx=10)

    # File operations
    file_frame = customtkinter.CTkFrame(master=frame, fg_color="transparent")
    file_frame.grid(row=6, column=0, columnspan=2, pady=10)

    upload_button = create_action_button(
        file_frame, "Upload File",
        lambda: upload_file(message_entry),
        "#4895EF"
    )
    upload_button.pack(side="left", padx=10)

    download_button = create_action_button(
        file_frame, "Download Result",
        lambda: download_file(result_display.get("1.0", "end-1c")),
        "#4CC9F0"
    )
    download_button.pack(side="left", padx=10)

    # Home button
    home_button = create_nav_button(
        frame, "Back to Home", open_home_scene, "#F72585"
    )
    home_button.grid(row=7, column=0, columnspan=2, pady=20)

def generateKeys():
    """Generate RSA keys with fixed primes for demonstration"""
    p = 7919  # Fixed prime for demo
    q = 1009  # Fixed prime for demo
    
    n = p * q
    phi = (p - 1) * (q - 1)

    # Find e where 1 < e < phi and gcd(e, phi) == 1
    e = 2
    while e < phi:
        if gcd(e, phi) == 1:
            break
        e += 1

    # Compute modular inverse d
    d = modInverse(e, phi)
    
    return e, d, n

def rsa_operation(operation, message, result_display, key, n):
    result_display.delete("1.0", "end")
    
    if not message:
        result_display.insert("1.0", "Error: Message cannot be empty")
        return
    
    if not message.isdigit():
        result_display.insert("1.0", "Error: Message can only contain numbers (0-9)")
        return
    
    try:
        if operation == "encrypt":
            # For text messages, encrypt character by character
            if message.isdigit():
                # Direct number encryption
                encrypted = power(int(message), key, n)
                result = f"Encrypted number: {encrypted}"
            else:
                # Text message - encrypt each character
                encrypted = [power(ord(char), key, n) for char in message]
                result = f"Encrypted message:\n{' '.join(map(str, encrypted))}"
        else:
            # Decryption
            if message.isdigit():
                # Direct number decryption
                decrypted = power(int(message), key, n)
                result = f"Decrypted number: {decrypted}"
            else:
                # Split encrypted numbers and decrypt
                nums = list(map(int, message.split()))
                decrypted = ''.join([chr(power(num, key, n)) for num in nums])
                result = f"Decrypted message:\n{decrypted}"
                
        result_display.insert("1.0", result)
    except Exception as e:
        result_display.insert("1.0", f"Error: {str(e)}")
    
def upload_file(message_entry):
    """Upload a text file to the message field"""
    filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if filename:
        try:
            with open(filename, 'r') as file:
                message_entry.delete(0, 'end')
                message_entry.insert(0, file.read())
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {str(e)}")

def download_file(content):
    """Download the result to a text file"""
    filename = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text files", "*.txt")]
    )
    if filename:
        try:
            with open(filename, 'w') as file:
                file.write(content)
            messagebox.showinfo("Success", "File saved successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {str(e)}")

# RSA helper functions
def power(base, exp, mod):
    """Modular exponentiation"""
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp = exp // 2
    return result

def gcd(a, b):
    """Greatest common divisor"""
    while b:
        a, b = b, a % b
    return a

def modInverse(e, phi):
    """Modular inverse using extended Euclidean algorithm"""
    g, x, y = extended_gcd(e, phi)
    if g != 1:
        return None  # No inverse exists
    else:
        return x % phi

def extended_gcd(a, b):
    """Extended Euclidean algorithm"""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)
       
#------------------------------------HELM----------------------------------------

def power(a, b, p): 
    return pow(a, b, p)

def open_diffie_hellman_scene():
    clear_frame()

    # Title
    title_label = customtkinter.CTkLabel(
        master=frame,
        text="DIFFIE-HELLMAN KEY EXCHANGE",
        font=("Roboto", 24, "bold"),
        text_color="#4CC9F0"
    )
    title_label.grid(row=0, column=0, columnspan=2, pady=(30, 10))

    # Input fields
    labels = ["Prime (P):", "Primitive Root (G):", "Alice Private Key (a):", "Bob Private Key (b):"]
    entries = []

    for i, text in enumerate(labels):
        label = customtkinter.CTkLabel(master=frame, text=text, font=("Roboto", 14))
        label.grid(row=i + 1, column=0, sticky="e", padx=10, pady=5)

        entry = customtkinter.CTkEntry(master=frame, width=200)
        entry.grid(row=i + 1, column=1, padx=10, pady=5)
        entries.append(entry)

    result_label = customtkinter.CTkLabel(master=frame, text="Result:", font=("Roboto", 14))
    result_label.grid(row=5, column=0, sticky="e", padx=10, pady=10)

    result_entry = customtkinter.CTkEntry(master=frame, width=300)
    result_entry.grid(row=5, column=1, padx=10, pady=10)

    def calculate_diffie_hellman():
        result_entry.delete(0, customtkinter.END)

        # Validate inputs
        for i, entry in enumerate(entries):
            value = entry.get().strip()
            if not value:
                result_entry.insert(0, f"Error: '{labels[i]}' cannot be empty")
                messagebox.showerror("Input Error", f"'{labels[i]}' cannot be empty")
                return
            if not value.isdigit():
                result_entry.insert(0, f"Error: '{labels[i]}' must be a number")
                messagebox.showerror("Input Error", f"'{labels[i]}' must be a number without letters or symbols")
                return
            if int(value) <= 0:
                result_entry.insert(0, f"Error: '{labels[i]}' must be a positive number")
                messagebox.showerror("Input Error", f"'{labels[i]}' must be a positive number")
                return

        try:
            P = int(entries[0].get())
            G = int(entries[1].get())
            a = int(entries[2].get())
            b = int(entries[3].get())

            # Additional logical checks
            if P <= 2:
                result_entry.insert(0, "Error: P must be a prime number greater than 2")
                messagebox.showerror("Input Error", "P must be a prime number greater than 2")
                return
            if a >= P or b >= P:
                result_entry.insert(0, "Error: Private keys must be less than P")
                messagebox.showerror("Input Error", "Private keys must be less than P")
                return

            # Step-by-step Diffie-Hellman
            x = power(G, a, P)  # Alice sends to Bob
            y = power(G, b, P)  # Bob sends to Alice

            ka = power(y, a, P)  # Alice computes
            kb = power(x, b, P)  # Bob computes

            if ka == kb:
                result = f"Shared Secret Key: {ka}"
            else:
                result = "Error: Key mismatch!"

            result_entry.insert(0, result)

        except ValueError:
            result_entry.insert(0, "Error: Please enter valid integers")
            messagebox.showerror("Input Error", "Please enter valid integers for all inputs")

    def upload_file_diffie(entries_list):
        filename = filedialog.askopenfilename(
            initialdir="/",
            title="Select file",
            filetypes=(("Text files", ".txt"), ("All files", ".*"))
        )
        if filename:
            with open(filename, "r") as file:
                lines = file.readlines()
                for i in range(min(4, len(lines))):
                    entries_list[i].delete(0, customtkinter.END)
                    entries_list[i].insert(0, lines[i].strip())

    def download_result():
        content = result_entry.get()
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=(("Text files", ".txt"), ("All files", ".*"))
        )
        if filename:
            with open(filename, "w") as file:
                file.write(content)

    # Buttons
    customtkinter.CTkButton(
        master=frame,
        text="Generate Key",
        command=calculate_diffie_hellman,
        fg_color="#7209B7"
    ).grid(row=6, column=0, columnspan=2, pady=10)

    customtkinter.CTkButton(
        master=frame,
        text="Upload File",
        command=lambda: upload_file_diffie(entries),
        fg_color="#4895EF"
    ).grid(row=7, column=0, columnspan=2, pady=5)

    customtkinter.CTkButton(
        master=frame,
        text="Download Result",
        command=download_result,
        fg_color="#4CC9F0"
    ).grid(row=8, column=0, columnspan=2, pady=5)

    customtkinter.CTkButton(
        master=frame,
        text="Back to Home",
        command=open_home_scene,
        fg_color="#F72585"
    ).grid(row=9, column=0, columnspan=2, pady=20)


open_home_scene()
root.mainloop()   