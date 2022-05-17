from app import app, controllers
from flask import render_template, request, redirect, url_for, flash, abort
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
    page = request.args.get('p') or '1'
    if not isinstance(page, str) or not page.isdigit() or int(page) < 1 or int(page) > 100000:
        return abort(404)
    page = int(page)
    error, alert_list, total_pages = controllers.get_alerts(50 * page, 50 * (page - 1))
    return render_template('alerts.html', alerts=alert_list, alerts_error=error, total_pages=total_pages,
                           curr_page=page)


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
