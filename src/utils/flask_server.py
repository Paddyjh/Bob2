from flask import Flask
import argparse

app = Flask(__name__)


@app.route('/', methods=['GET'])
def home():
    return "Hello, World!", 200


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Run Flask app on a custom port.")
    parser.add_argument('--port', type=int, default=8189,
                        help='Port number to run the Flask app on.')
    args = parser.parse_args()

    # Run the app on the specified port
    app.run(debug=True, port=args.port)
