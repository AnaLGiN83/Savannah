from app import app, controllers
from flask import render_template, request, redirect, url_for, flash
from flask_login import login_required, logout_user, current_user


@app.route('/')
@login_required
def index():
    return render_template('index.html')


@app.route('/alerts')
@login_required
def alerts():
    return render_template('alerts.html')


@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')


@app.route('/auth', methods=['GET'])
def auth_get():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    return render_template('auth.html')


@app.route('/auth', methods=['POST'])
def auth_post():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    username = request.form.get('username')
    password = request.form.get('password')
    if username and password and controllers.authenticate(username, password):
        return redirect(url_for('index'))
    flash("Invalid username or password.", "error")
    return redirect(url_for('auth_get'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for('auth_get'))
