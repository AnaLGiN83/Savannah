from flask import Flask, render_template

app = Flask(__name__)  # TODO: Проработать архитектуру для app в корректном месте


@app.route('/')
def index():
    return render_template('index.html')
