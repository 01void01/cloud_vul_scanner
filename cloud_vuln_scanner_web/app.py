from flask import Flask
from app.routes import routes_bp
import os

app = Flask(__name__, template_folder='app/templates')
app.secret_key = "super-secret-key"

app.register_blueprint(routes_bp)

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)

