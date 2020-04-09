class callargs(tuple):
    """
    A tuple for holding the results of a call to a mock, either in the form
    `(args, kwargs)` or `(name, args, kwargs)`.
    If args or kwargs are empty then a callargs tuple will compare equal to
    a tuple without those values. This makes comparisons less verbose::
        callargs('name', (), {}) == ('name',)
        callargs('name', (1,), {}) == ('name', (1,))
        callargs((), {'a': 'b'}) == ({'a': 'b'},)
    """
    def __eq__(self, other):
        if len(self) == 3:
            if other[0] != self[0]:
                return False
            args_kwargs = self[1:]
            other_args_kwargs = other[1:]
        else:
            args_kwargs = tuple(self)
            other_args_kwargs = other

        if len(other_args_kwargs) == 0:
            other_args, other_kwargs = (), {}
        elif len(other_args_kwargs) == 1:
            if isinstance(other_args_kwargs[0], tuple):
                other_args = other_args_kwargs[0]
                other_kwargs = {}
            else:
                other_args = ()
                other_kwargs = other_args_kwargs[0]
        else:
            other_args, other_kwargs = other_args_kwargs

        return tuple(args_kwargs) == (other_args, other_kwargs)


class Recorder(object):
    def __init__(self):
        self.call_list = []

    def expect(self, *args, **kwargs):
        ''' if ignore_args is true, we do not check the args anymore '''
        return_value = kwargs.pop('return_value', None)
        side_effect = kwargs.pop('side_effect', None)
        ignore_args = kwargs.pop('ignore_args', None)
        call_spec = (callargs((args, kwargs)),
                     return_value, side_effect, ignore_args)
        self.call_list.append(call_spec)

    def assert_end(self):
        if self.call_list != []:
            raise AssertionError("Expected calls not realized (%d calls)" %
                                 len(self.call_list))

    def __call__(self, *args, **kwargs):
        if not self.call_list:
            raise AssertionError("Mock object called more times than expected")
        expected_args, return_value, side_effect, ignore_args = \
            self.call_list.pop(0)
        if not ignore_args and expected_args != callargs((args, kwargs)):
            raise AssertionError('Expected: %s\nCalled with: %s' %
                                 (expected_args, (args, kwargs)))
        if side_effect is not None:
            raise side_effect
        else:
            return return_value
