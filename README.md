# 📘 Special Headers — Burp Suite Extension
### A clean, customizable HTTP header viewer for Burp Suite  
**Created and maintained by Arshia**

---

## ⭐ Overview

**Header Viewer+**, developed by **Arshia**, is a Burp Suite extension written in Python (Jython) that adds a dedicated tab for inspecting HTTP headers of any request or response.  
It focuses solely on headers, providing a clean and highly customizable interface with filtering, highlighting, and persistent settings.

The extension also includes an advanced live header counter that updates even when the tab is not active.

---

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

### ✔ Export / Import Settings
- Export your configuration to a file  
- Import on another device or share with teammates  
- Helps maintain consistent testing environments

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
| Normal headers | **Bold + Blue** |
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

Developed fully in Python for use with Jython inside Burp Suite.

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

