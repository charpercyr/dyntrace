
debug=True

def debug_print(*args, **kwargs):
    if debug:
        print(*args, **kwargs)


def set_debug(val):
    global debug
    debug = val