from app import app, controllers
from flask import render_template, request, redirect, url_for, flash, abort
from flask_login import login_required, logout_user, current_user
from .models import User


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


@app.route('/settings', methods=['GET'])
@login_required
def settings_get():
    if not current_user.is_admin:
        return abort(404)
    suricata_error, suricata_log = controllers.get_suricata_log()
    return render_template('settings.html', suricata_error=suricata_error, suricata_log=suricata_log)


@app.route('/settings', methods=['POST'])
@login_required
def settings_post():
    if not current_user.is_admin:
        return abort(404)
    req_type = request.form.get('req_type')
    if req_type and req_type == 'suricata-update':
        error, data = controllers.update_rules()
        if error:
            return f"Error code {error}\n" + (data or "")
        else:
            return data


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


@app.route('/users', methods=['GET'])
@login_required
def users_get():
    if not current_user.is_admin:
        return abort(404)
    users = list(User.select(User.id, User.username, User.name, User.is_admin, User.created_on).dicts())
    return render_template('users.html', users=users)


@app.route('/users', methods=['POST'])
@login_required
def users_post():
    if not current_user.is_admin:
        return abort(404)
    req_type = request.form.get('req_type')
    if req_type == "add_user":
        username = request.form.get('username')
        password = request.form.get('password')
        name = request.form.get('name')
        is_admin = request.form.get('is_admin')
        if username and password and 0 < len(username.strip()) <= 50 and 4 < len(password) <= 100:
            controllers.create_user(username, password, is_admin or False, name)
    elif req_type == "edit_user":
        action = request.form.get('action')
        target = request.form.get('target_user')
        if not action or not target or not target.isdigit() or current_user.id == int(target):
            return redirect(url_for('users_get'))
        target = int(target)
        if action == "make_admin":
            controllers.set_user_admin_by_id(target, True)
        elif action == "deadmin":
            controllers.set_user_admin_by_id(target, False)
        elif action == "delete":
            controllers.delete_user_by_id(target)
    return redirect(url_for('users_get'))
