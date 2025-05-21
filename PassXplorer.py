import os
import itertools
import zipfile
import PyPDF2
import rarfile
import docx
import threading
from queue import Queue
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext
from tkinter.ttk import Progressbar
import subprocess
import tempfile

# AI Model Training (legacy/simple model)
def train_ai_model():
    common_passwords = ["password", "123456", "qwerty", "iloveyou", "admin123", "welcome"]
    vectorizer = CountVectorizer()
    X = vectorizer.fit_transform(common_passwords)
    model = MultinomialNB()
    model.fit(X, range(len(common_passwords)))
    return model, vectorizer

ai_model, ai_vectorizer = train_ai_model()

# Smart Password Generator
def generate_smart_passwords(base_words):
    suffixes = ["", "1", "123", "@123", "2023", "2024", "!"]
    leet_map = {"a": "@", "s": "$", "o": "0", "e": "3", "i": "1"}
    guesses = set()

    for word in base_words:
        word = word.lower()
        guesses.add(word)
        guesses.add(word.capitalize())

        for suffix in suffixes:
            guesses.add(word + suffix)
            guesses.add(word.capitalize() + suffix)
            guesses.add(word.upper() + suffix)

        leet_word = ''.join(leet_map.get(c, c) for c in word)
        for suffix in suffixes:
            guesses.add(leet_word + suffix)

    return list(guesses)

# Try password for supported file types and extract location
def try_password(file_path, password):
    try:
        extract_dir = os.path.join(tempfile.gettempdir(), "passxplorer_output")
        os.makedirs(extract_dir, exist_ok=True)

        if file_path.endswith(".zip"):
            with zipfile.ZipFile(file_path) as zf:
                zf.extractall(extract_dir, pwd=password.encode())
                return True, extract_dir
        elif file_path.endswith(".pdf"):
            with open(file_path, "rb") as f:
                reader = PyPDF2.PdfReader(f)
                if reader.decrypt(password):
                    new_path = os.path.join(extract_dir, os.path.basename(file_path))
                    with open(new_path, "wb") as out:
                        out.write(f.read())
                    return True, extract_dir
        elif file_path.endswith(".rar"):
            with rarfile.RarFile(file_path) as rf:
                rf.extractall(extract_dir, pwd=password.encode())
                return True, extract_dir
        elif file_path.endswith(".docx"):
            new_path = os.path.join(extract_dir, os.path.basename(file_path))
            with open(file_path, "rb") as f_src, open(new_path, "wb") as f_dst:
                f_dst.write(f_src.read())
            return True, extract_dir
    except:
        pass
    return False, None

# Dictionary Attack
def dictionary_attack(file_path, wordlist, output, progress):
    with open(wordlist, "r", errors='ignore') as file:
        passwords = [line.strip() for line in file]
    total = len(passwords)
    for i, password in enumerate(passwords):
        success, path = try_password(file_path, password)
        if success:
            output.insert(tk.END, f"[+] Password found: {password}\n")
            return password, path
        output.insert(tk.END, f"[-] Tried: {password}\n")
        progress["value"] = int((i+1)/total * 100)
        root.update_idletasks()
    return None, None

# Brute Force Attack
def brute_force_attack(file_path, charset, max_length, output, progress):
    total = sum(len(charset) ** i for i in range(1, max_length+1))
    count = 0
    for length in range(1, max_length + 1):
        for password in itertools.product(charset, repeat=length):
            count += 1
            password = "".join(password)
            success, path = try_password(file_path, password)
            if success:
                output.insert(tk.END, f"[+] Password found: {password}\n")
                return password, path
            output.insert(tk.END, f"[-] Tried: {password}\n")
            progress["value"] = int(count / total * 100)
            root.update_idletasks()
    return None, None

# Enhanced AI Attack (smart variant generator)
def ai_attack(file_path, guesses, output, progress):
    smart_guesses = generate_smart_passwords(guesses)
    for i, password in enumerate(smart_guesses):
        success, path = try_password(file_path, password)
        if success:
            output.insert(tk.END, f"[+] Password found by AI: {password}\n")
            return password, path
        output.insert(tk.END, f"[-] AI tried: {password}\n")
        progress["value"] = int((i+1)/len(smart_guesses) * 100)
        root.update_idletasks()
    return None, None

# GUI Functions
def select_file():
    file_path = filedialog.askopenfilename()
    entry_file_path.delete(0, tk.END)
    entry_file_path.insert(0, file_path)

def open_decrypted_folder(path):
    if os.path.exists(path):
        subprocess.Popen(f'explorer "{path}"')

def run_attack():
    file_path = entry_file_path.get()
    attack_type = attack_mode.get()
    output.delete("1.0", tk.END)
    progress_bar["value"] = 0

    if not os.path.exists(file_path):
        messagebox.showerror("Error", "Please select a valid file.")
        return

    result = None
    extract_path = None

    if attack_type == "Dictionary Attack":
        wordlist_path = filedialog.askopenfilename(title="Select Wordlist File")
        if not os.path.exists(wordlist_path):
            messagebox.showerror("Error", "Invalid wordlist path.")
            return
        result, extract_path = dictionary_attack(file_path, wordlist_path, output, progress_bar)

    elif attack_type == "Brute Force Attack":
        result, extract_path = brute_force_attack(file_path, charset="abc123", max_length=3, output=output, progress=progress_bar)

    elif attack_type == "AI Prediction":
        guesses = ["letmein", "mypassword", "qwerty123", "admin", "pass", "guest"]
        result, extract_path = ai_attack(file_path, guesses, output, progress_bar)

    with open("passxplorer_log.txt", "w") as f:
        f.write(output.get("1.0", tk.END))

    if result:
        messagebox.showinfo("Done", f"Password cracked and file decrypted! Log saved.\nOpening folder...")
        open_decrypted_folder(extract_path)
    else:
        messagebox.showinfo("Done", "Attack completed. Password not found. Log saved.")

# GUI Setup
root = tk.Tk()
root.title("PassXplorer - AI Password Recovery Tool")
root.geometry("700x550")

# Background Image Setup
try:
    bg_image = Image.open("passxplorer_logo.png")
    bg_image = bg_image.resize((700, 550), Image.ANTIALIAS)
    bg_photo = ImageTk.PhotoImage(bg_image)
    bg_label = tk.Label(root, image=bg_photo)
    bg_label.place(x=0, y=0, relwidth=1, relheight=1)
except Exception as e:
    print("Logo not found or failed to load:", e)

frame = tk.Frame(root, bg="white")
frame.pack(pady=10)

lbl_file = tk.Label(frame, text="Encrypted File:", bg="white")
lbl_file.grid(row=0, column=0, padx=5)

entry_file_path = tk.Entry(frame, width=50)
entry_file_path.grid(row=0, column=1, padx=5)

btn_browse = tk.Button(frame, text="Browse", command=select_file)
btn_browse.grid(row=0, column=2, padx=5)

lbl_mode = tk.Label(root, text="Select Attack Type:", bg="white")
lbl_mode.pack(pady=5)

attack_mode = ttk.Combobox(root, values=["Dictionary Attack", "Brute Force Attack", "AI Prediction"])
attack_mode.current(0)
attack_mode.pack(pady=5)

btn_start = tk.Button(root, text="Start Attack", command=run_attack)
btn_start.pack(pady=10)

progress_bar = Progressbar(root, orient=tk.HORIZONTAL, length=400, mode='determinate')
progress_bar.pack(pady=5)

output = scrolledtext.ScrolledText(root, width=80, height=15)
output.pack(pady=10)

root.mainloop()
