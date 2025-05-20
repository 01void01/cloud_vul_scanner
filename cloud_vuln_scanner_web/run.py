import subprocess
import sys
import os

def install_requirements():
    try:
        import flask  # Try importing Flask to check if already installed
    except ImportError:
        print("🔧 Installing dependencies from requirements.txt...")

        req_path = os.path.join(os.path.dirname(__file__), "requirements.txt")
        if not os.path.isfile(req_path):
            print("❌ requirements.txt not found at", req_path)
            sys.exit(1)

        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", req_path])
            print("✅ Dependencies installed successfully.")
        except subprocess.CalledProcessError as e:
            print("❌ pip install failed:", e)
            sys.exit(1)

def run_app():
    print("🚀 Starting Flask app...\n")
    os.execv(sys.executable, [sys.executable, "app.py"])

if __name__ == "__main__":
    install_requirements()
    run_app()
