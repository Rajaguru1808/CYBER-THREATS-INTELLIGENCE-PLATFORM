"""Authentication routes: login, logout, and (admin-only) user registration."""
from datetime import datetime

from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user

from app.extensions import db
from app.models.user import User
from app.models.activity_log import ActivityLog
from app.utils.validators import is_valid_username, is_valid_email, is_strong_password
from app.utils.decorators import admin_required

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Please enter both username and password.', 'danger')
            return render_template('login.html')

        user = User.query.filter(
            (User.username == username) | (User.email == username)
        ).first()

        if user is None or not user.check_password(password):
            flash('Invalid username or password.', 'danger')
            ActivityLog.log(None, 'LOGIN_FAILED', f'Failed login attempt for "{username}"',
                             request.remote_addr)
            return render_template('login.html')

        if not user.is_active:
            flash('This account has been disabled. Contact an administrator.', 'danger')
            return render_template('login.html')

        login_user(user)
        user.last_login = datetime.utcnow()
        db.session.commit()
        ActivityLog.log(user.id, 'LOGIN', f'{user.username} logged in', request.remote_addr)

        next_page = request.args.get('next')
        flash(f'Welcome back, {user.full_name or user.username}!', 'success')
        return redirect(next_page or url_for('dashboard.index'))

    return render_template('login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    ActivityLog.log(current_user.id, 'LOGOUT', f'{current_user.username} logged out',
                     request.remote_addr)
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/users', methods=['GET'])
@login_required
@admin_required
def manage_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('settings.html', users=users, active_tab='users')


@auth_bp.route('/users/create', methods=['POST'])
@login_required
@admin_required
def create_user():
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    full_name = request.form.get('full_name', '').strip()
    password = request.form.get('password', '')
    role = request.form.get('role', 'analyst')

    errors = []
    if not is_valid_username(username):
        errors.append('Username must be 3-50 characters (letters, numbers, . _ -).')
    if not is_valid_email(email):
        errors.append('Please provide a valid email address.')
    if not is_strong_password(password):
        errors.append('Password must be at least 8 characters and include a letter and a number.')
    if role not in ('admin', 'analyst'):
        errors.append('Invalid role selected.')
    if User.query.filter((User.username == username) | (User.email == email)).first():
        errors.append('A user with that username or email already exists.')

    if errors:
        for e in errors:
            flash(e, 'danger')
        return redirect(url_for('auth.manage_users'))

    user = User(username=username, email=email, full_name=full_name, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    ActivityLog.log(current_user.id, 'CREATE_USER', f'Created user {username} ({role})',
                     request.remote_addr)
    flash(f'User "{username}" created successfully.', 'success')
    return redirect(url_for('auth.manage_users'))


@auth_bp.route('/users/<int:user_id>/toggle-active', methods=['POST'])
@login_required
@admin_required
def toggle_user_active(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot disable your own account.', 'warning')
        return redirect(url_for('auth.manage_users'))
    user.is_active_flag = not user.is_active_flag
    db.session.commit()
    ActivityLog.log(current_user.id, 'TOGGLE_USER',
                     f'Set {user.username} active={user.is_active_flag}', request.remote_addr)
    flash(f'User "{user.username}" is now {"active" if user.is_active_flag else "disabled"}.', 'success')
    return redirect(url_for('auth.manage_users'))
