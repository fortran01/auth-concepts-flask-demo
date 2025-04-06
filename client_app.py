from flask import Flask, render_template

app = Flask(__name__)
app.debug = True

@app.route('/')
def index():
    """
    Main page that demonstrates CORS through various examples
    """
    return render_template('cors_demo.html')

if __name__ == '__main__':
    # Run the client app on port 5003 (different from API server)
    app.run(host='0.0.0.0', port=5003) 