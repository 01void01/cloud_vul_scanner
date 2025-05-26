# 🔒 Cloud Infrastructure Vulnerability Scanner

This is a Flask-based web application that scans various AWS services (S3, EC2, IAM, RDS, EBS) for common security misconfigurations and vulnerabilities. It provides detailed scan results with severity levels, descriptions, and remediation steps — all displayed in an interactive dashboard. You can also export the results as a PDF report.

---

## 📸 Screenshot

> screenshot

## 🚀 Features

- 🌐 Web-based interface built with Flask
- 🔑 Supports AWS access key-based scanning
- ✅ Services scanned:
  - S3 (e.g. public access, logging)
  - EC2 (e.g. open ports)
  - IAM (e.g. no MFA, old access keys)
  - RDS (e.g. publicly accessible instances)
  - EBS (e.g. unattached volumes, no encryption)
- 📊 Interactive scan results dashboard with severity badges
- 📂 Results grouped by service in collapsible dropdowns
- 🛠️ In-app remediation guidance
- 📄 Export results to PDF report

---

## 📁 Project Structure

```
cloud-scanner/
│
├── app/
│   ├── templates/
│   │   ├── dashboard.html
│   │   └── pdf_template.html
│   ├── scanners/
│   │   ├── s3_scanner.py
│   │   ├── ec2_scanner.py
│   │   ├── iam_scanner.py
│   │   ├── rds_scanner.py
│   │   └── ebs_scanner.py
│   └── routes.py
├── app.py
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/cloud-scanner.git
cd cloud-scanner
```

### 2. Create and activate a virtual environment

```bash
python -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## 🧪 Run the app locally

```bash
python app.py
```

Then open your browser and go to:  
`http://127.0.0.1:5000/`

---

## 📌 Usage

1. Enter your **AWS Access Key**, **Secret Key**, and **Region**.
2. Choose a scan type (individual service or full scan).
3. Click "Scan" to begin.
4. Results will be grouped under service dropdowns.
5. Click "View Fix" to see remediation.
6. Use the **Export PDF** button to download the scan report.

> **Important**: Use test or sandbox AWS credentials — not production keys.

---

## 📄 Requirements

- Python 3.7+
- Flask
- Boto3
- xhtml2pdf

---

## 📤 Deployment

You can deploy the app on:

- 🐳 Docker (Dockerfile can be added)
- ☁️ AWS EC2 / Lightsail
- 🔁 Gunicorn + Nginx for production

---

## ❗ Security Note

- Your credentials are not stored. But **do not use real production AWS credentials**.
- For production use, consider integrating **STS tokens**, **IAM roles**, or **OAuth flow** for better security.

---

## 🧑‍💻 Author

- **Ankit** – Final Year BCA Student | Specialization: Cloud & Security

---

## 📃 License

This project is licensed under the MIT License — feel free to fork and build on it!