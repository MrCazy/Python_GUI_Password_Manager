import tkinter
import tkinter.messagebox
import customtkinter
import base64
import os
import time

customtkinter.set_appearance_mode("System")  # Modes: "System" (standard), "Dark", "Light"
customtkinter.set_default_color_theme("dark-blue")  # Themes: "blue" (standard), "green", "dark-blue"

class Loginpage(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        # configure window
        self.title("Update Master Password")
        self.geometry(f"{320}x{360}")
        self.resizable(0, 0)

        # configure grid layout (4x3)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure((0, 2), weight=0)
        self.grid_rowconfigure((0, 1, 2, 3, 4, 5), weight=1)

        self.current_password_label = customtkinter.CTkLabel(self, text="Log in",font=('Century Gothic',20), anchor="w")
        self.current_password_label.grid(row=0, column=1, padx=20, pady=(20, 10))

        self.current_password_entry = customtkinter.CTkEntry(self, placeholder_text="Enter password", show="*")
        self.current_password_entry.grid(row=1, column=1, padx=20, pady=(0, 5))

        self.forgot_password_label = customtkinter.CTkLabel(self, text="Forgot password?", anchor="w", text_color="white", cursor="hand2")
        self.forgot_password_label.grid(row=2, column=1, padx=20, pady=(5, 10))
        self.forgot_password_label.bind("<Button-1>", self.forgot_password)

        def on_enter(event):
            self.forgot_password_label.configure(text_color="blue")

        def on_leave(event):
            self.forgot_password_label.configure(text_color="white")

        self.forgot_password_label.bind("<Enter>", on_enter)
        self.forgot_password_label.bind("<Leave>", on_leave)

        self.login_button = customtkinter.CTkButton(self, text="Login", command=self.verify_master_password)
        self.login_button.grid(row=4, column=1, padx=20, pady=(15, 20))

    def verify_master_password(self):
        entered_password = self.current_password_entry.get()
        with open("master_password.txt", "r") as file:
            secret = file.readline()
        master_password = self.decrypt("secret_key", secret)
        master_password = master_password.strip()  # Remove trailing newline character
        if entered_password == master_password:
            self.destroy()
            app = App()
            app.mainloop()
        else:
            ()
        
    def forgot_password(self, event):
        # This method will be called when the "Forgot password?" label is clicked
        self.destroy()
        app = forgotpassword(self)
        app.mainloop()
    
    def decrypt(self, key, encrypt):
        decrypt = []
        encrypt = base64.urlsafe_b64decode(encrypt).decode()
        for index, characters in enumerate(encrypt):
            key_c = key[index % len(key)]
            dec_c = chr((256 + ord(characters) - ord(key_c)) % 256)
            decrypt.append(dec_c)
        return "".join(decrypt)

class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        
        # configure window
        self.title("Password Manager")
        self.geometry(f"{700}x{480}")
        self.resizable(0, 0)

        # configure grid layout (4x4)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure((2, 3), weight=0)
        self.grid_rowconfigure((0, 1, 2), weight=1)

        if os.path.isfile('passwords.txt') == False:
            with open("passwords.txt", "w") as file:
                file.write("")
            file.close()

        # create sidebar frame with widgets
        self.sidebar_frame = customtkinter.CTkFrame(self, width=140, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=8, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)

        self.logo_label = customtkinter.CTkLabel(self.sidebar_frame, text="Password manager", font=customtkinter.CTkFont('Century Gothic',20))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.sidebar_show_button = customtkinter.CTkButton(self.sidebar_frame, command=self.show_passwords, cursor="hand2")
        self.sidebar_show_button.grid(row=1, column=0, padx=20, pady=10)

        self.sidebar_hide_button = customtkinter.CTkButton(self.sidebar_frame, command=self.clear_textbox, cursor="hand2")
        self.sidebar_hide_button.grid(row=2, column=0, padx=20, pady=10)

        self.sidebar_delete_button = customtkinter.CTkButton(self.sidebar_frame, command=self.open_are_you_sure_window)
        self.sidebar_delete_button.grid(row=3, column=0, padx=20, pady=10)

        self.change_master_password_button = customtkinter.CTkButton(self.sidebar_frame, text="Update master password", command=self.open_change_master_password_window)
        self.change_master_password_button.grid(row=6, column=0, padx=20, pady=10)

        self.appearance_mode_label = customtkinter.CTkLabel(self.sidebar_frame, text="Appearance Mode:", anchor="w")
        self.appearance_mode_label.grid(row=7, column=0, padx=20, pady=(10, 0))

        self.appearance_mode_optionemenu = customtkinter.CTkOptionMenu(self.sidebar_frame, values=["Light", "Dark", "System"], command=self.change_appearance_mode_event)
        self.appearance_mode_optionemenu.grid(row=8, column=0, padx=20, pady=(10, 10))

        # create textbox
        self.textbox = customtkinter.CTkTextbox(self, width=250)
        self.textbox.grid(row=0, column=1, padx=(20, 15), pady=(20, 0), sticky="nsew")

        self.website_label = customtkinter.CTkLabel(self, text="Save password")
        self.website_label.grid(row=1, column=1, padx=(20, 0), pady=(0, 0), sticky="nsew")

        self.website_entry = customtkinter.CTkEntry(self, placeholder_text="Enter website")
        self.website_entry.grid(row=2, column=1, padx=(20, 0), pady=(0, 0), sticky="w")

        self.username_entry = customtkinter.CTkEntry(self, placeholder_text="Enter username")
        self.username_entry.grid(row=3, column=1, padx=(20, 10), pady=(0, 18), sticky="w")

        self.password_entry = customtkinter.CTkEntry(self, placeholder_text="Enter password", show="*")
        self.password_entry.grid(row=4, column=1, padx=(20, 0), pady=(0, 10), sticky="w")

        self.save_button = customtkinter.CTkButton(self, text="Save", command=self.save_password)
        self.save_button.grid(row=3, column=1, padx=(20, 20), pady=(10, 29), sticky="e")
        
        # set default values
        self.textbox.insert("0.0", "Passwords\n\n")
        self.textbox.configure(state="disabled")
        self.sidebar_show_button.configure(text="Show passwords", cursor="hand2")
        self.sidebar_hide_button.configure(state = "disabled", text="Hide passwords", cursor="hand2")
        self.sidebar_delete_button.configure(text="Delete passwords")
        self.appearance_mode_optionemenu.set("Dark")

    def clear_textbox(self):
        self.textbox.configure(state="normal")
        self.textbox.delete("1.0", customtkinter.END)
        self.sidebar_hide_button.configure(state = "disabled", text="Hide passwords", cursor="hand2")
        self.sidebar_show_button.configure(state = "normal", text="Show passwords", cursor="hand2")
        self.textbox.insert("0.0", "Passwords\n\n")
        self.textbox.configure(state="disabled")
        
    def open_change_master_password_window(self):
        app = UpdateMasterPasswordWindow(self)
        app.mainloop()

    def open_are_you_sure_window(self):
        app = Areyousurepage(self)
        app.mainloop()

    def save_password(self):
        website = self.website_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        self.textbox.configure(state="normal")
        if website == "" or username == "" or password == "":
            self.textbox.delete("1.0", customtkinter.END)
            self.textbox.insert("0.0", "Passwords\n\n Enter all details before saving")
            self.textbox.configure(state="disabled")
            self.after(3000, self.clear_textbox) # call clear_textbox
            self.sidebar_hide_button.configure(state = "disabled", text="Hide passwords", cursor="hand2")
            self.sidebar_show_button.configure(state = "normal", text="Show passwords", cursor="hand2")
            return
        encrypted_password = self.encrypt("secret_key", password)
        with open("passwords.txt", "a") as file:
            file.write(f"{website}:{username}:{encrypted_password}\n")
        self.textbox.delete("1.0", customtkinter.END)
        self.textbox.insert("0.0", "Passwords\n\n Password saved")
        self.textbox.configure(state="disabled")
        self.after(3000, self.clear_textbox) # call clear_textbox
        self.website_entry.delete(0, customtkinter.END)
        self.username_entry.delete(0, customtkinter.END)
        self.password_entry.delete(0, customtkinter.END)

    def show_passwords(self):
        try:
            self.textbox.configure(state="normal")
            self.textbox.delete("1.0", customtkinter.END)
            self.textbox.insert("0.0", "Passwords\n\n")
            self.textbox.configure(state="disabled")
            with open("passwords.txt", "r") as file:
                lines = file.readlines()
            if os.stat("passwords.txt").st_size == 0:
                self.textbox.configure(state="normal", foreground="white")
                self.textbox.insert(customtkinter.END, "Error: No passwords saved")
                self.textbox.configure(state="disabled")
                self.after(3000, self.clear_textbox)
                return
            passwords = []
            self.sidebar_show_button.configure(state="disabled", text="Show passwords", cursor="hand2")
            self.sidebar_hide_button.configure(state="normal", text="Hide passwords", cursor="hand2")
            for line in lines:
                website, username, encrypted_password = line.strip().split(":")
                try:
                    password = self.decrypt("secret_key", encrypted_password)
                except Exception as decryption_error:
                    self.textbox.configure(state="normal")
                    self.textbox.insert(customtkinter.END, f"Error displaying {website} details: Decryption error\n\n")
                    self.textbox.configure(state="disabled")
                    continue
                passwords.append((website, username, password))
            if not passwords:
                self.textbox.configure(state="normal")
                self.textbox.insert(customtkinter.END, f"Error: No passwords to display\n")
                self.textbox.configure(state="disabled")
                self.after(3000, self.clear_textbox)
            else:
                self.textbox.configure(state="normal")
                self.textbox.insert(customtkinter.END, "\n".join([f"{website}: \nUsername: {username} \nPassword: {password}" '\n' for website, username, password in passwords]))
                self.textbox.configure(state="disabled")
        except Exception as error_message:
            self.textbox.delete("1.0", customtkinter.END)
            self.textbox.insert(customtkinter.END, f"Error: No passwords to display\n")
            self.textbox.configure(state="disabled")
            self.after(3000, self.clear_textbox)
  
    def encrypt(self, key, clear):
        encrypt = []
        for index, characters in enumerate(clear):
            key_c = key[index % len(key)]
            enc_c = chr((ord(characters) + ord(key_c)) % 256)
            encrypt.append(enc_c)
        return base64.urlsafe_b64encode("".join(encrypt).encode()).decode()

    def decrypt(self, key, encrypt):
        decrypt = []
        encrypt = base64.urlsafe_b64decode(encrypt).decode()
        for index, characters in enumerate(encrypt):
            key_c = key[index % len(key)]
            dec_c = chr((256 + ord(characters) - ord(key_c)) % 256)
            decrypt.append(dec_c)
        return "".join(decrypt)

    def change_appearance_mode_event(self, new_appearance_mode: str):
        customtkinter.set_appearance_mode(new_appearance_mode)

class CreateMasterPassword(customtkinter.CTk):
    def __init__(self, app):
        super().__init__()

        self.app = app

        # configure window
        self.title("Create Master Password")
        self.geometry(f"{350}x{450}")
        self.resizable(0, 0)

        # configure grid layout (4x3)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure((0, 2), weight=0)
        self.grid_rowconfigure((0, 1, 2, 3, 4, 5, 6, 7), weight=1)

        self.master_password_label = customtkinter.CTkLabel(self, text="Create Master Password:", anchor="w")
        self.master_password_label.grid(row=0, column=1, padx=20, pady=(30, 10))

        self.master_password_entry = customtkinter.CTkEntry(self, placeholder_text="Enter password", show="*")
        self.master_password_entry.grid(row=1, column=1, padx=20, pady=(0, 10))

        self.confirm_password_label = customtkinter.CTkLabel(self, text="Confirm Master Password:", anchor="w")
        self.confirm_password_label.grid(row=2, column=1, padx=20, pady=(0, 10))

        self.confirm_password_entry = customtkinter.CTkEntry(self, placeholder_text="Re-enter password", show="*")
        self.confirm_password_entry.grid(row=3, column=1, padx=20, pady=(0, 0))

        self.error_label = customtkinter.CTkLabel(self, text="", text_color='red')
        self.error_label.grid(row=4, column=1, pady=(0, 30))

        self.favorite_food_label = customtkinter.CTkLabel(self, text="What is your favourite food?", anchor="w")
        self.favorite_food_label.grid(row=4, column=1, padx=20, pady=(60, 5))

        self.favorite_food_entry = customtkinter.CTkEntry(self, placeholder_text="Answer", show="*")
        self.favorite_food_entry.grid(row=5, column=1, padx=20, pady=(0, 10))

        self.Update_button = customtkinter.CTkButton(self, text="Create", command=self.create_master_password)
        self.Update_button.grid(row=7, column=1, padx=20, pady=(0, 20))

    def create_master_password(self):
        master_password = self.master_password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        favourite_food = self.favorite_food_entry.get()

        if len(master_password) < 8:
            self.error_label.configure(text="Password must be at least 8 characters long")
            return
        elif master_password != confirm_password:
            self.error_label.configure(text="Passwords do not match")
            return

        encrypted_password = self.encrypt("secret_key", master_password)
        encrypted_food = self.encrypt("secret_key", favourite_food)
        with open("master_password.txt", "w") as file:
            file.write(encrypted_password + "\n" + encrypted_food)
        file.close()
        self.destroy()
        app = App()
        app.mainloop()

    def encrypt(self, key, clear):
        encrypt = []
        for index, characters in enumerate(clear):
            key_c = key[index % len(key)]
            enc_c = chr((ord(characters) + ord(key_c)) % 256)
            encrypt.append(enc_c)
        return base64.urlsafe_b64encode("".join(encrypt).encode()).decode()

class UpdateMasterPasswordWindow(customtkinter.CTk):
    def __init__(self, app):
        super().__init__()

        self.app = app

        # configure window
        self.title("Update Master Password")
        self.geometry(f"{400}x{380}")
        self.resizable(0, 0)

        # configure grid layout (4x3)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure((0, 2), weight=0)
        self.grid_rowconfigure((0, 1, 2, 3, 4, 5, 6, 7), weight=1)

        self.current_password_label = customtkinter.CTkLabel(self, text="Enter current password", anchor="w")
        self.current_password_label.grid(row=0, column=1, padx=20, pady=(20, 10))

        self.current_password_entry = customtkinter.CTkEntry(self, placeholder_text="Current password", show="*")
        self.current_password_entry.grid(row=1, column=1, padx=20, pady=(0, 20))

        self.new_password_label = customtkinter.CTkLabel(self, text="Create new master password", anchor="w")
        self.new_password_label.grid(row=3, column=1, padx=20, pady=(5, 10))

        self.new_password_entry = customtkinter.CTkEntry(self, placeholder_text="New password", show="*")
        self.new_password_entry.grid(row=4, column=1, padx=20, pady=(0, 20))

        self.confirm_password_label = customtkinter.CTkLabel(self, text="Confirm password", anchor="w")
        self.confirm_password_label.grid(row=5, column=1, padx=20, pady=(5, 10))

        self.confirm_password_entry = customtkinter.CTkEntry(self, placeholder_text="Re-enter password", show="*")
        self.confirm_password_entry.grid(row=6, column=1, padx=20, pady=(0, 20))

        self.Update_button = customtkinter.CTkButton(self, text="Update", command=self.update_master_password)
        self.Update_button.grid(row=7, column=1, padx=20, pady=(15, 20))
        
    def update_master_password(self):
        current_password = self.current_password_entry.get()
        with open("master_password.txt", "r") as file:
            secret = file.readline()
        master_password = self.decrypt("secret_key", secret)
        master_password = master_password.strip()  # Remove trailing newline character
        if current_password == master_password:
            new_password = self.new_password_entry.get()
            confirm_password = self.confirm_password_entry.get()
            if confirm_password != new_password:
                return
            with open("master_password.txt", "w") as file:
                file.write(self.encrypt("secret_key", new_password))
            time.sleep(1)
            self.destroy()
            app = App()
            app.mainloop()
        else:
            # Display error
            ()

    def encrypt(self, key, clear):
        encrypt = []
        for index, characters in enumerate(clear):
            key_c = key[index % len(key)]
            enc_c = chr((ord(characters) + ord(key_c)) % 256)
            encrypt.append(enc_c)
        return base64.urlsafe_b64encode("".join(encrypt).encode()).decode()

    def decrypt(self, key, encrypt):
        decrypt = []
        encrypt = base64.urlsafe_b64decode(encrypt).decode()
        for index, characters in enumerate(encrypt):
            key_c = key[index % len(key)]
            dec_c = chr((256 + ord(characters) - ord(key_c)) % 256)
            decrypt.append(dec_c)
        return "".join(decrypt)

class forgotpassword(customtkinter.CTk):
    def __init__(self, app):
        super().__init__()

        self.app = app

        # configure window
        self.title("Update Master Password")
        self.geometry(f"{400}x{380}")
        self.resizable(0, 0)

        # configure grid layout (4x3)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure((0, 2), weight=0)
        self.grid_rowconfigure((0, 1, 2, 3, 4, 5, 6, 7), weight=1)

        self.favourite_food_label = customtkinter.CTkLabel(self, text="What is your favourite food?", anchor="w")
        self.favourite_food_label.grid(row=0, column=1, padx=20, pady=(20, 10))

        self.favourite_food_entry = customtkinter.CTkEntry(self, placeholder_text="Answer", show="*")
        self.favourite_food_entry.grid(row=1, column=1, padx=20, pady=(0, 20))

        self.new_password_label = customtkinter.CTkLabel(self, text="Create new master password", anchor="w")
        self.new_password_label.grid(row=3, column=1, padx=20, pady=(5, 10))

        self.new_password_entry = customtkinter.CTkEntry(self, placeholder_text="New password", show="*")
        self.new_password_entry.grid(row=4, column=1, padx=20, pady=(0, 20))

        self.confirm_password_label = customtkinter.CTkLabel(self, text="Confirm password", anchor="w")
        self.confirm_password_label.grid(row=5, column=1, padx=20, pady=(5, 10))

        self.confirm_password_entry = customtkinter.CTkEntry(self, placeholder_text="Re-enter password", show="*")
        self.confirm_password_entry.grid(row=6, column=1, padx=20, pady=(0, 20))

        self.Update_button = customtkinter.CTkButton(self, text="Update", command=self.update_master_password)
        self.Update_button.grid(row=7, column=1, padx=20, pady=(15, 20))
        
    def update_master_password(self):
        favourite_food = self.favourite_food_entry.get()
        with open("master_password.txt", "r") as file:
            secret = file.readlines()
        encrypted_food = self.decrypt("secret_key", secret[1])
        encrypted_food = encrypted_food.strip()  # Remove trailing newline character
        if encrypted_food == favourite_food:
            new_password = self.new_password_entry.get()
            confirm_password = self.confirm_password_entry.get()
            if confirm_password != new_password:
                return
            encrypted_password = self.encrypt("secret_key", new_password)
            with open("master_password.txt", "w") as file:
                file.write(encrypted_password + "\n" + secret[1])
            self.destroy()
            app = App()
            app.mainloop()
        else:
            # Display error
            ()

    def encrypt(self, key, clear):
        encrypt = []
        for index, characters in enumerate(clear):
            key_c = key[index % len(key)]
            enc_c = chr((ord(characters) + ord(key_c)) % 256)
            encrypt.append(enc_c)
        return base64.urlsafe_b64encode("".join(encrypt).encode()).decode()

    def decrypt(self, key, encrypt):
        decrypt = []
        encrypt = base64.urlsafe_b64decode(encrypt).decode()
        for index, characters in enumerate(encrypt):
            key_c = key[index % len(key)]
            dec_c = chr((256 + ord(characters) - ord(key_c)) % 256)
            decrypt.append(dec_c)
        return "".join(decrypt)

class Areyousurepage(customtkinter.CTk):
    def __init__(self, app):
        super().__init__()

        self.app = app

        # configure window
        self.title("Confirm")
        self.geometry(f"{200}x{180}")
        self.resizable(0, 0)

        # configure grid layout (4x3)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure((0, 2), weight=0)
        self.grid_rowconfigure((0, 1, 2, 3), weight=1)

        self.sure_label = customtkinter.CTkLabel(self, text="Are you sure?", anchor="w")
        self.sure_label.grid(row=0, column=1, padx=20, pady=(20, 10))

        self.yes_button = customtkinter.CTkButton(self, text="Yes", command=self.clear_file)
        self.yes_button.grid(row=2, column=1, padx=20, pady=(15, 20))

        self.no_button = customtkinter.CTkButton(self, text="No", command=self.clickno)
        self.no_button.grid(row=3, column=1, padx=20, pady=(0, 20))
    
    def clickno(self):
        self.destroy()

    def clear_file(self):
        self.destroy()
        with open('passwords.txt', 'w') as file:
            file.write('')
        file.close()

if os.path.isfile('master_password.txt') == False or os.stat("master_password.txt").st_size == 0:
    create_master_password_window = CreateMasterPassword(App())
    create_master_password_window.mainloop()
else:
    app = Loginpage()
    app.mainloop()