import hashlib
import tkinter as tk
from tkinter import Button, Label, Text, ttk, Frame
from PIL import Image, ImageTk

def calcular_hashes():
    contrasena = entrada_contrasena.get("1.0", "end-1c").encode('utf-8')
    
    md5 = hashlib.md5(contrasena).hexdigest()
    sha1 = hashlib.sha1(contrasena).hexdigest()
    sha224 = hashlib.sha224(contrasena).hexdigest()
    sha256 = hashlib.sha256(contrasena).hexdigest()
    sha384 = hashlib.sha384(contrasena).hexdigest()
    sha512 = hashlib.sha512(contrasena).hexdigest()

    resultado_text.config(state="normal")
    resultado_text.delete("1.0", "end")
    resultado_text.insert("end", f"Hash MD5:\n{md5}\n", "hash")
    resultado_text.insert("end", "\n" + "-" * 40 + "\n")
    resultado_text.insert("end", f"Hash SHA1:\n{sha1}\n", "hash")
    resultado_text.insert("end", "\n" + "-" * 40 + "\n")
    resultado_text.insert("end", f"Hash SHA224:\n{sha224}\n", "hash")
    resultado_text.insert("end", "\n" + "-" * 40 + "\n")
    resultado_text.insert("end", f"Hash SHA256:\n{sha256}\n", "hash")
    resultado_text.insert("end", "\n" + "-" * 40 + "\n")
    resultado_text.insert("end", f"Hash SHA384:\n{sha384}\n", "hash")
    resultado_text.insert("end", "\n" + "-" * 40 + "\n")
    resultado_text.insert("end", f"Hash SHA512:\n{sha512}\n", "hash")
    resultado_text.tag_config("hash", foreground="green")

    resultado_text.config(state="disabled")

def seleccionar_hash(event):
    cursor_pos = resultado_text.index(tk.CURRENT)
    text = resultado_text.get(cursor_pos + " linestart", cursor_pos + " lineend")
    entrada_desencriptar.delete("1.0", "end")
    entrada_desencriptar.insert("1.0", text)

def dark_mode():
    window.configure(bg='#6C7A89')
    style.configure('TLabel', background='#6C7A89', foreground='#FFFFFF', font=('Arial', 12, 'bold'))
    style.configure('TButton', background='#95A5A6', foreground='#2C3E50', padding=5, font=('Arial', 12, 'bold'))
    style.configure('TText', background='black', foreground='green', font=('Arial', 12))

def desencriptar_hashes():
    resolverhash = entrada_desencriptar.get("1.0", "end-1c")
    tipo = tipo_encriptacion.get()

    resultado_text.config(state="normal")
    resultado_text.delete("1.0", "end")

    resolvedor = open("PASS.TXT", 'r')

    for x in resolvedor.readlines():
        a = x.strip("\n").encode('utf-8')

        if tipo == 'md5':
            a = hashlib.md5(a).hexdigest()
        elif tipo == 'sha1':
            a = hashlib.sha1(a).hexdigest()
        elif tipo == 'sha224':
            a = hashlib.sha224(a).hexdigest()
        elif tipo == 'sha256':
            a = hashlib.sha256(a).hexdigest()
        elif tipo == 'sha384':
            a = hashlib.sha384(a).hexdigest()
        elif tipo == 'sha512':
            a = hashlib.sha512(a).hexdigest()
        else:
            raise Exception('El tipo de encriptación %s no es válido.' % tipo)

        if a == resolverhash:
            resultado_text.insert("end", f"Contraseña:\n{x.rstrip()}\n", "result")
            resultado_text.insert("end", f"Has resuelto:\n{a}\n", "result")
            resultado_text.tag_bind("result", "<Button-1>", lambda event: seleccionar_hash(event))
            resultado_text.config(state="disabled")
            break

def agregar_contrasena():
    contrasena = entrada_contrasena.get("1.0", "end-1c")
    
    with open("PASS.TXT", 'a') as archivo:
        archivo.write(contrasena + '\n')

    entrada_contrasena.delete("1.0", "end")

window = tk.Tk()
window.title("Encriptador de Contraseña")
window.geometry("400x600")
window.configure(bg='#6C7A89')
window.resizable(False, False)
window.attributes('-alpha', 0.95)

style = ttk.Style()
style.configure('TLabel', background='#6C7A89', foreground='#FFFFFF', font=('Arial', 12, 'bold'))
style.configure('TButton', background='#95A5A6', foreground='#2C3E50', padding=5, font=('Arial', 12, 'bold'))
style.configure('TText', background='black', foreground='green', font=('Arial', 12))

dark_mode_button = Button(window, text="Modo Oscuro", command=dark_mode)
dark_mode_button.pack(pady=10)

frame = Frame(window, background='#95A5A6', bd=5, relief=tk.RAISED)
frame.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

label_contrasena = Label(frame, text="Contraseña:", background='#95A5A6', foreground='#2C3E50')
label_contrasena.pack()

entrada_contrasena = Text(frame, height=1, width=40)
entrada_contrasena.pack()


agregar_button = Button(frame, text="Agregar Contraseña", command=agregar_contrasena, background='#2ECC71', foreground='#2C3E50', relief=tk.RAISED)
agregar_button.pack(pady=10)

calcular_button = Button(frame, text="Calcular Hashes", command=calcular_hashes, background='#2ECC71', foreground='#2C3E50', relief=tk.RAISED)
calcular_button.pack(pady=10)


label_desencriptar = Label(frame, text="Hash a Desencriptar:", background='#95A5A6', foreground='#2C3E50')
label_desencriptar.pack()

entrada_desencriptar = Text(frame, height=1, width=40)
entrada_desencriptar.pack()

tipo_encriptacion = ttk.Combobox(frame, values=['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'], style='TButton')
tipo_encriptacion.pack()

desencriptar_button = Button(frame, text="Desencriptar Hash", command=desencriptar_hashes, background='#2ECC71', foreground='#2C3E50', relief=tk.RAISED)
desencriptar_button.pack(pady=10)

resultado_text = Text(window, height=15, width=40, background='black', foreground='green', bd=5, relief=tk.RAISED)
resultado_text.pack(padx=20, pady=10)

resultado_text.config(state="disabled")

window.mainloop()
