import tkinter
import tkinter.messagebox
import customtkinter
import base64
import os

customtkinter.set_appearance_mode("System")  # Modes: "System" (standard), "Dark", "Light"
customtkinter.set_default_color_theme("dark-blue")  # Themes: "blue" (standard), "green", "dark-blue"

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
        self.logo_label = customtkinter.CTkLabel(self.sidebar_frame, text="Password manager", font=customtkinter.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
        self.sidebar_button_1 = customtkinter.CTkButton(self.sidebar_frame, command=self.show_passwords)
        self.sidebar_button_1.grid(row=1, column=0, padx=20, pady=10)
        self.sidebar_button_2 = customtkinter.CTkButton(self.sidebar_frame, command=self.clear_textbox)
        self.sidebar_button_2.grid(row=2, column=0, padx=20, pady=10)
        self.sidebar_button_3 = customtkinter.CTkButton(self.sidebar_frame, command=self.clear_file)
        self.sidebar_button_3.grid(row=3, column=0, padx=20, pady=10)
        self.master_password_label = customtkinter.CTkLabel(self.sidebar_frame, text="Master Password:", anchor="w")
        self.master_password_label.grid(row=4, column=0, padx=20, pady=(25, 0))

        self.master_password_entry = customtkinter.CTkEntry(self.sidebar_frame, placeholder_text="Enter password", show="*")
        self.master_password_entry.grid(row=5, column=0, padx=20, pady=(0, 20))

        self.verify_button = customtkinter.CTkButton(self.sidebar_frame, text="Verify", command=self.verify_master_password)
        self.verify_button.grid(row=6, column=0, padx=20, pady=(0, 50))
        self.appearance_mode_label = customtkinter.CTkLabel(self.sidebar_frame, text="Appearance Mode:", anchor="w")
        self.appearance_mode_label.grid(row=7, column=0, padx=20, pady=(10, 0))
        self.appearance_mode_optionemenu = customtkinter.CTkOptionMenu(self.sidebar_frame, values=["Light", "Dark", "System"],
                                                                       command=self.change_appearance_mode_event)
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
        self.textbox.insert("0.0", "Passwords\n\nEnter master password")
        self.sidebar_button_1.configure(state = "disabled", text="Show passwords")
        self.sidebar_button_2.configure(state = "disabled", text="Hide passwords")
        self.sidebar_button_3.configure(state = "disabled", text="Delete passwords")
        self.save_button.configure(state = "disabled")
        self.appearance_mode_optionemenu.set("Dark")

    def clear_file(self):
        self.textbox.delete("1.0", customtkinter.END)
        with open('passwords.txt', 'w') as file:
            file.write('')
        self.textbox.insert("1.0", "Passwords\n\nAll passwords cleared\n")
        self.after(3000, self.clear_textbox) # call clear_textbox after 5000 milliseconds (5 seconds)

    def clear_textbox(self):
        self.textbox.delete("1.0", customtkinter.END)
        self.sidebar_button_2.configure(state = "disabled", text="Hide passwords")
        self.sidebar_button_1.configure(state = "enabled", text="Show passwords")
        self.textbox.insert("0.0", "Passwords\n\n")

    def verify_master_password(self):
        entered_password = self.master_password_entry.get()
        master_password = "hi" # Replace with your own master password
        if entered_password == master_password:
            # Passwords match, do something
            self.textbox.delete("1.0", customtkinter.END)
            self.textbox.insert("1.0", "Passwords\n\nMaster password verified\nYou can start using the program")
            self.after(3000, self.clear_textbox) # call clear_textbox after 5000 milliseconds (5 seconds)
            self.sidebar_button_1.configure(state = "enabled", text="Show passwords")
            self.sidebar_button_3.configure(state = "enabled", text="Delete passwords")
            self.verify_button.configure(state = "disabled")
            self.master_password_entry.delete(0, customtkinter.END)
            self.master_password_entry.configure(state = "disabled")
            self.save_button.configure(state = "enabled")
            self.website_entry.configure(state = "normal")
            self.username_entry.configure(state = "normal")
            self.password_entry.configure(state = "normal")
        else:
            # Passwords do not match, display error message
            self.textbox.delete("1.0", customtkinter.END)
            self.textbox.insert("1.0", "Passwords\n\nError: Master password incorrect")
            self.master_password_entry.delete(0, customtkinter.END)

    def save_password(self):
        website = self.website_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        if website == "" or username == "" or password == "":
            self.textbox.delete("1.0", customtkinter.END)
            self.textbox.insert("0.0", "Passwords\n\n Enter all details before saving")
            self.after(3000, self.clear_textbox) # call clear_textbox after 5000 milliseconds (5 seconds)
            self.sidebar_button_2.configure(state = "disabled", text="Hide passwords")
            self.sidebar_button_1.configure(state = "enabled", text="Show passwords")
            return
        encrypted_password = self.encrypt("secret_key", password)
        with open("passwords.txt", "a") as file:
            file.write(f"{website}:{username}:{encrypted_password}\n")
        self.textbox.delete("1.0", customtkinter.END)
        self.textbox.insert("0.0", "Passwords\n\n Password saved")
        self.after(3000, self.clear_textbox) # call clear_textbox after 5000 milliseconds (5 seconds)
        self.website_entry.delete(0, customtkinter.END)
        self.username_entry.delete(0, customtkinter.END)
        self.password_entry.delete(0, customtkinter.END)

    def show_passwords(self):
        try:
            self.textbox.delete("1.0", customtkinter.END)
            self.textbox.insert("0.0", "Passwords\n\n")
            with open("passwords.txt", "r") as file:
                lines = file.readlines()
            size = os.stat("passwords.txt").st_size == 0

            if size == True:
                self.textbox.configure(state="normal", foreground="white")
                self.textbox.insert(0, customtkinter.END, "Error: No passwords saved")
                self.after(3000, self.clear_textbox) # call clear_textbox after 5000 milliseconds (5 seconds)
                return
            passwords = []
            self.sidebar_button_1.configure(state = "disabled", text="Show passwords")
            self.sidebar_button_2.configure(state = "enabled", text="Hide passwords")
            for i, line in enumerate(lines):
                website, username, encrypted_password = line.strip().split(":")
                try:
                    password = self.decrypt("secret_key", encrypted_password)
                except Exception as e:
                    self.textbox.configure(state="normal")
                    self.textbox.insert(customtkinter.END, f"Error displaying {website} details: Decryption error\n\n")
                    continue
                passwords.append((website, username, password))
            if not passwords:
                self.textbox.configure(state="normal")
                self.textbox.insert(customtkinter.END, "No passwords to display\n")
                self.after(3000, self.clear_textbox) # call clear_textbox after 5000 milliseconds (5 seconds)
            else:
                self.textbox.configure(state="normal")
                self.textbox.insert(customtkinter.END, "\n".join([f"{website}: \nUsername: {username} \nPassword: {password}" '\n' for website, username, password in passwords]))
        except Exception as e:
            self.textbox.delete("1.0", customtkinter.END)
            self.textbox.insert(customtkinter.END, "Passwords\n\nNo passwords to display\n")
            self.after(3000, self.clear_textbox) # call clear_textbox after 5000 milliseconds (5 seconds)
  
    def encrypt(self, key, clear):
        enc = []
        for i, c in enumerate(clear):
            key_c = key[i % len(key)]
            enc_c = chr((ord(c) + ord(key_c)) % 256)
            enc.append(enc_c)
        return base64.urlsafe_b64encode("".join(enc).encode()).decode()

    def decrypt(self, key, enc):
        dec = []
        enc = base64.urlsafe_b64decode(enc).decode()
        for i, c in enumerate(enc):
            key_c = key[i % len(key)]
            dec_c = chr((256 + ord(c) - ord(key_c)) % 256)
            dec.append(dec_c)
        return "".join(dec)

    def change_appearance_mode_event(self, new_appearance_mode: str):
        customtkinter.set_appearance_mode(new_appearance_mode)

if __name__ == "__main__":
    app = App()
    app.mainloop()