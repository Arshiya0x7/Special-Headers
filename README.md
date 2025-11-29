# 📘 Special Headers — Burp Suite Extension
### A clean, customizable HTTP header viewer for Burp Suite  
**Created and maintained by Arshia**

---

## ⭐ Overview

**Special Headers**, developed by **Arshia0X7**, is a Burp Suite extension written in Python (Jython) that adds a dedicated tab for inspecting HTTP headers of any request or response.  

This plugin is for displaying custom headers of all requests and responses.  

By providing two lists:  
- 1. Headers that do not need to be displayed  
- 2. Headers that should be highlighted 
It displays the custom headers in a tab named "Headers".

It focuses solely on headers, providing a clean and highly customizable interface with filtering, highlighting, and persistent settings.
The extension also includes an advanced live header counter that updates when the tab is active.

---

<img width="1493" height="509" alt="image" src="https://github.com/user-attachments/assets/23ee3962-4610-4215-9837-8856fa3664b8" />


## 🚀 Features

### ✔ Dedicated “Headers” Tab
- Shows only headers (no body, no other data)  
- Displays request & response headers  
- Live-updating counter: **Headers (12)**

---

### ✔ Filter Unwanted Headers
- Hide specific headers from the display  
- Case-insensitive  
- Persistent storage  
- Clean & minimal UI for managing lists

---

### ✔ Highlight Important Headers
- Selected headers appear in **bold red**  
- Normal headers appear as **bold blue**  
- Only the header *name* is colorized for better visibility

---

### ✔ Persistent Configuration
- Your filters and highlights are saved automatically  
- Restored every time Burp starts  
- No need to re-enter lists each time

---

### ✔ Live Header Counting
- Header count updates automatically  
- Works even when the “Headers” tab is not open  
- Smooth navigation in Proxy history with always-accurate numbers

---

## 🎨 Header Display Style

| Header Type | Style |
|-------------|--------|
| Highlighted headers | **Bold + Red** |
| Normal headers | **Bold + White** |
| Header values | Gray-ish (`#a9b7c6`) |

---

## 📂 Installation

### **1. Installing Manually**
1. Go to **Burp → Extensions → Add**  
2. Extension Type: **Python**  
3. Select the file: `HeaderViewerPlus.py`  
4. Click **Next** → Loaded successfully

---

### **2. Through BApp Store**
(When published)

---

## ⚙ Settings Included

- Manage **Hidden Headers** list  
- Manage **Highlighted Headers** list  
- Auto-save configuration  
- Export / Import settings  
- Clean UI built with Swing

---

## 🧠 Technical Notes

This extension uses:
- `IMessageEditorTab`
- `ITab`
- `IHttpListener`
- `IExtensionStateListener`

Developed fully in Python for use with Jython2.7.3 inside Burp Suite.

---

## 👤 Author

This extension is **created and maintained by Arshia**.  
Focused on:
- Web Security  
- Burp Suite automation  
- Tool development for penetration testers

---

## 📝 License
MIT License

---

## ⭐ Contributions
Pull requests and feature suggestions are welcome.  
Feel free to open issues on GitHub.

