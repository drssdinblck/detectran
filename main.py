from butter.fanotify import FAN_MODIFY, FAN_ONDIR, FAN_ACCESS, FAN_EVENT_ON_CHILD, FAN_OPEN
from butter.fanotify import FAN_CLOSE, FAN_ALLOW, FAN_DENY
#  Permission events
from butter.fanotify import FAN_OPEN_PERM, FAN_ACCESS_PERM

#  fanotify_init
from butter.fanotify import Fanotify, FAN_CLASS_NOTIF, FAN_CLASS_PRE_CONTENT, FAN_CLASS_CONTENT

from collections import defaultdict

import os
import gzip
from concurrent.futures import ThreadPoolExecutor


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
    with open(event.filename, 'rb') as f:
        size = os.path.getsize(event.filename)
        read_len = size if size < 16 * 1024 else 16 * 1024
        b = f.read(read_len)
        return 1.0 if len(b) == 0 else float(len(gzip.compress(b))) / len(b)


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


def loop_events():
    watchdir = '/home/appsec/Testfanotify'
    notifier = Fanotify(FAN_CLASS_CONTENT)
    mask = FAN_MODIFY | FAN_EVENT_ON_CHILD | FAN_OPEN_PERM | FAN_ACCESS_PERM
    notifier.watch(watchdir, mask)
    os.listdir(watchdir)

    self_event_worker = ThreadPoolExecutor(4)
    ext_event_worker = ThreadPoolExecutor(1)

    for event in notifier:
        if event.pid == os.getpid():
            self_event_worker.submit(handle_self_emitted_event, notifier, event)
        else:
            ext_event_worker.submit(handle_external_event, notifier, event)

        print_event(event)
        print(file_stats)
        print(proc_stats)
        print()

    notifier.close()


def handle_external_event(notifier, event):
    if event.open_perm_event or event.access_perm_event:
        file_stats[event.filename]['ent'] = est_entropy(event)
        allow_event(notifier, event)
    elif event.modify_event:
        ent_before = file_stats[event.filename]['ent']
        ent_after = est_entropy(event)
        proc_stats[event.pid][event.filename]['ent_ratio'] = ent_after / ent_before
        file_stats[event.filename]['ent'] = ent_after

    event.close()


def handle_self_emitted_event(notifier, event):
    if event.open_perm_event or event.access_perm_event:
        allow_event(notifier, event)

    event.close()


if __name__ == '__main__':
    # data = bytes('a'*1000000, encoding='us-ascii')
    # print(len(gzip.compress(data)))
    loop_events()
