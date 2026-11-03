"""Custom decorators for access control (RBAC: admin vs analyst)."""
from functools import wraps
from flask import abort, flash, redirect, url_for, request, jsonify
from flask_login import current_user


def admin_required(f):
    """Restrict a route to users with the 'admin' role only."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        if not current_user.is_admin():
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Admin privileges required'}), 403
            flash('Admin privileges are required to access that page.', 'danger')
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    return decorated


def analyst_or_admin_required(f):
    """Allow both analyst and admin roles (i.e. any authenticated + active user)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        if current_user.role not in ('admin', 'analyst'):
            abort(403)
        return f(*args, **kwargs)
    return decorated
