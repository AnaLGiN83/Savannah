from app import app, controllers
from flask import render_template, request, redirect, url_for, flash
from flask_login import login_required, logout_user, current_user


@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('auth_get'))
    error, stats = controllers.get_last_stats()
    return render_template('index.html', stats=stats, stats_error=error, daemon_status=controllers.get_daemon_status())


@app.route('/alerts')
@login_required
def alerts():
    error, alert_list = controllers.get_alerts()
    return render_template('alerts.html', alerts=alert_list, alerts_error=error)


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
