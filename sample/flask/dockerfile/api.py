from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    return "flask api is working"


if __name__ == "__main__":
    # Get Parameter
    app.run(host='0.0.0.0', port=8080)
