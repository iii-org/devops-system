from flask import Flask
import gitlab
app = Flask(__name__)


@app.route("/")
def index():
    return "api is working"

@app.route("/create", methods=['GET', 'POST'])
def DevOpsCreateAPI():
    if flask_req.method == 'GET':
        return "DevOps create api is working"
    elif flask_req.method == 'POST':
        # Jenkins, return token
        # gitlab
        # SonarQube create job
        # carete sonnaer container
    else:
        return "API method not POST or GET"

if __name__ == "__main__":
    # Get Parameter
    app.run(host='0.0.0.0', port=10009)
