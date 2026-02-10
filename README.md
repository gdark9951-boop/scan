# 🔐 Mustafa & Ahmed: Universal Website Scanner

![Cyber Security Scanner](https://img.shields.io/badge/Security-Scanner-00f5ff?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge)
![Flask](https://img.shields.io/badge/Flask-3.1.2-green?style=for-the-badge)

## 🚀 Description

A powerful web-based security scanning tool with a stunning Cyber HUD interface. Scan websites for vulnerabilities, check ports, enumerate subdomains, and more!

## ✨ Features

- 🎯 **Advanced Vulnerability Detection** - Metasploit-style intelligence engine
- 🛰️ **Port Scanning** - Nmap-style deep port analysis
- 🌐 **Subdomain Enumeration** - DNS-based discovery
- 🔍 **Path Discovery** - Sensitive file detection
- 📊 **Security Headers Analysis** - OWASP best practices check
- 💾 **Export Reports** - Save scan results as JSON
- 🎨 **Beautiful Cyber HUD UI** - Modern, responsive interface

## 🔧 Installation

### Local Setup

```bash
# Clone the repository
git clone <your-repo-url>
cd <project-folder>

# Install dependencies
pip install -r requirements.txt

# Run the application
python mustafa3mk.py
```

Then open your browser and navigate to: `http://localhost:5000`

## 🌍 Deploy to Render (Free Hosting)

### Step 1: Create a GitHub Repository

1. Go to [GitHub](https://github.com) and create a new repository
2. Initialize git in your project folder:

```bash
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
git push -u origin main
```

### Step 2: Deploy on Render

1. Go to [Render.com](https://render.com) and sign up (free)
2. Click **"New +"** → **"Web Service"**
3. Connect your GitHub repository
4. Configure:
   - **Name**: `mustafa-scanner` (or any name you like)
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn mustafa3mk:app --bind 0.0.0.0:$PORT --timeout 300`
   - **Instance Type**: `Free`
5. Click **"Create Web Service"**
6. Wait 5-10 minutes for deployment
7. Your app will be live at: `https://your-app-name.onrender.com`

## 📝 Usage

1. Enter target URL (e.g., `https://example.com`)
2. Click **"🚀 [ EXECUTE SCAN ]"**
3. Wait for scan to complete
4. View results in the console
5. Click buttons to see detailed reports:
   - **METASPLOIT STRIKE** - Full vulnerability report
   - **NMAP POWER** - Port scan results
   - **SUBDOMAIN SCAN** - Discovered subdomains
   - **SITE INTEL** - Metadata and headers
   - **SAVE REPORT** - Export to JSON

## ⚠️ Disclaimer

This tool is for **EDUCATIONAL PURPOSES** and **AUTHORIZED SECURITY TESTING** only. 

- Always obtain proper authorization before scanning any website
- Unauthorized scanning may be illegal in your jurisdiction
- The authors are not responsible for misuse of this tool

## 🛡️ Security Notice

- This scanner performs non-intrusive reconnaissance
- No exploitation attempts are made
- All scans are read-only operations
- Use responsibly and ethically

## 📜 License

For educational and research purposes only.

## 👨‍💻 Authors

**Mustafa & Ahmed** - Cyber Security Researchers

---

**⚡ Live Demo**: [Deploy on Render and update this link]

**🐛 Report Issues**: [GitHub Issues](https://github.com/YOUR_USERNAME/YOUR_REPO_NAME/issues)

**⭐ Star us on GitHub if you find this useful!**
