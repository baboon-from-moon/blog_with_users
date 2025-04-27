# def admin_only(func):
#     def wrapper():
#         print("Something before the function.")
#         func()
#         print("Something after the function.")
#     return wrapper

# @admin_only
# def testing():
#     print('Bon Jour!')


# testing()

# from functools import wraps
# from flask import redirect, url_for

# def login_required_custom(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if not current_user.is_authenticated:
#             return redirect(url_for('login'))
#         return f(*args, **kwargs)
#     return decorated_function

import os

print(os.environ.get('FLASK_KEY'))