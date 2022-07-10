from butter.fanotify import FAN_MODIFY, FAN_ONDIR, FAN_ACCESS, FAN_EVENT_ON_CHILD, FAN_OPEN
from butter.fanotify import FAN_CLOSE, FAN_ALLOW, FAN_DENY
#  Permission events
from butter.fanotify import FAN_OPEN_PERM, FAN_ACCESS_PERM

#  fanotify_init
from butter.fanotify import Fanotify, FAN_CLASS_NOTIF, FAN_CLASS_PRE_CONTENT, FAN_CLASS_CONTENT

from collections import defaultdict

import os


class PrintableDefaultDict(defaultdict):
    def __repr__(self):
        return dict.__repr__(self)


file_stats = PrintableDefaultDict(lambda: {})
proc_stats = PrintableDefaultDict(lambda: PrintableDefaultDict(lambda: {}))


def perm_response(event, allow_or_deny, endianness='little', order='fd_first'):
    fd_bytes = event.fd.to_bytes(4, byteorder=endianness, signed=True)

    if allow_or_deny == 'allow':
        msg_bytes = FAN_ALLOW.to_bytes(4, byteorder=endianness, signed=False)
    else:
        msg_bytes = FAN_DENY.to_bytes(4, byteorder=endianness, signed=False)

    response = fd_bytes + msg_bytes if order == 'fd_first' else msg_bytes + fd_bytes
    return response


def allow_event(notifier, event):
    os.write(notifier.fileno(), perm_response(event, 'allow'))


def deny_event(notifier, event):
    os.write(notifier.fileno(), perm_response(event, 'deny'))


def est_entropy(event, value=100):
    return value


def print_event(event):
    if event.open_perm_event:
        t = 'OPEN_PERM'
    elif event.modify_event:
        t = 'FAN_MODIFY'
    else:
        t = 'OTHER'

    print('{}[{}]'.format(t, event.filename))


def loop_events():
    watchdir = '/home/appsec/Testfanotify'
    notifier = Fanotify(FAN_CLASS_CONTENT)
    mask = FAN_MODIFY | FAN_EVENT_ON_CHILD | FAN_OPEN_PERM | FAN_ACCESS_PERM
    notifier.watch(watchdir, mask)
    os.listdir(watchdir)

    for event in notifier:
        assert event.filename.startswith(watchdir)

        if event.open_perm_event:
            file_stats[event.filename]['entropy'] = est_entropy(event, 100)
            allow_event(notifier, event)
        elif event.modify_event:
            ent_before = file_stats[event.filename]['entropy']
            ent_after = est_entropy(event, 200)
            proc_stats[event.pid][event.filename]['entropy_diff'] = ent_after - ent_before
            file_stats[event.filename]['entropy'] = ent_after

        event.close()

        print_event(event)
        print(file_stats)
        print(proc_stats)
        print()

    notifier.close()


if __name__ == '__main__':
    loop_events()
