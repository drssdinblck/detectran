import os
from signal import SIGKILL

#  fanotify events
from butter.fanotify import (
    FAN_OPEN_PERM, FAN_ACCESS_PERM, FAN_MODIFY, FAN_ONDIR, FAN_ACCESS,
    FAN_EVENT_ON_CHILD, FAN_OPEN
)

#  fanotify reponses
from butter.fanotify import FAN_ALLOW, FAN_DENY

#  fanotify_init
from butter.fanotify import (
    Fanotify, FAN_CLASS_NOTIF, FAN_CLASS_PRE_CONTENT, FAN_CLASS_CONTENT
)


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


def print_event(event):
    by_pid = 'self' if event.pid == os.getpid() else os.getpid()

    if event.open_perm_event:
        t = 'OPEN_PERM'
    elif event.modify_event:
        t = 'FAN_MODIFY'
    elif event.access_perm_event:
        t = 'FAN_ACCESS_PERM'
    else:
        t = 'OTHER'

    print('{}({})[{}]'.format(t, by_pid, event.filename))


def decide_trust_process(notifier, event):
    kill_trust_or_ignore = input("Kill process (k), trust process (t) or ignore event (i)").lower()
    if kill_trust_or_ignore.startswith('k'):
        print("KILL_PROCESS({})".format(event.pid))
        deny_event(notifier, event)
        os.kill(event.pid, SIGKILL)
    elif kill_trust_or_ignore.startswith('t'):
        print("TRUST_PROCESS({})".format(event.pid))
        allow_event(notifier, event)
        return True
    else:
        print("ALLOW_EVENT({})]".format(event.pid))
        allow_event(notifier, event)

    return False
