import os
import gzip
from collections import defaultdict

from butter_helper import print_event


class PrintableDefaultDict(defaultdict):
    def __repr__(self):
        return dict.__repr__(self)


def est_entropy(event):
    with open(event.filename, 'rb') as f:
        size = os.path.getsize(event.filename)
        read_len = size if size < 16 * 1024 else 16 * 1024
        b = f.read(read_len)
        return 1.0 if len(b) == 0 else float(len(gzip.compress(b))) / len(b)


def is_encrypting(ent_before, ent_after):
    return ent_before < 0.98 < ent_after


def prints_errors(func):
    def print_errors(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            print("Exception from {}: {}".format(func, e))
            raise e

    return print_errors


def prints_events(func):
    def with_printed_errors(*args, **kwargs):
        ret_val = func(*args, **kwargs)
        print_event(args[1])
        print()
        return ret_val

    return with_printed_errors


