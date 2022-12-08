from flask import Blueprint, redirect, render_template, flash, request, url_for
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash

auth = Blueprint('auth', __name__)


@auth.route('/login')
def login():
    return render_template('login.html')


@auth.route('/logout')
def logout():
    return '<h3>You have successfully logged out!</h3>'


@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('first-name')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        if len(email) < 4:
            flash('Email must be at least 4 characters in length.', category='error')
        elif len(first_name) < 2:
            flash('First name must be at least 2 characters in length.',
                  category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters in length.',
                  category='error')
        elif password1 != password2:
            flash('Passwords do not match', category='error')
        else:
            new_user = User(email=email, first_name=first_name,
                            password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()

            flash('Account created', category='success')
            return redirect(url_for('views.home'))

    return render_template('signup.html')
