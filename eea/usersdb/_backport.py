''' backport '''
# pylint: disable=unused-import
try:
    from functools import wraps
except ImportError:
    def wraps(func):
        ''' define our own wraps if functools is not available '''
        def decorator(wrapper):
            ''' decorator '''
            for name in ('__module__', '__name__', '__doc__'):
                setattr(wrapper, name, getattr(func, name))
                wrapper.__dict__.update(func.__dict__)
            return wrapper
        return decorator
