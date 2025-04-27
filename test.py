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

def debug(func):
    def wrapper(*args, **kwargs):
        print(f"Calling {func.__name__} with {args} and {kwargs}")
        return func(*args, **kwargs)
    return wrapper

@debug
def add(a, b):
    return a + b

print(add(a=3, b=5))