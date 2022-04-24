from app import app
from flask import render_template


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/alerts')
def alerts():
    return render_template('alerts.html')


@app.route('/settings')
def settings():
    return render_template('settings.html')
