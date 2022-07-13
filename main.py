from concurrent.futures import ThreadPoolExecutor
from my_utils import (
    PrintableDefaultDict, est_entropy, is_encrypting,
    prints_events, prints_errors
)

from butter_helper import *


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

    notifier.close()


@prints_errors
def handle_external_event(notifier, event):
    if event.open_perm_event or event.access_perm_event:
        if event.filename not in file_stats:
            file_stats[event.filename]['ent'] = est_entropy(event)

        allow_event(notifier, event)
    elif event.modify_event:
        ent_before = file_stats[event.filename]['ent']
        ent_after = est_entropy(event)
        proc_stats[event.pid][event.filename]['ent_before'] = ent_before
        proc_stats[event.pid][event.filename]['ent_after'] = ent_after
        file_stats[event.filename]['ent'] = ent_after

        if is_encrypting(ent_before, ent_after):
            print("PROBABLY_ENCRYPTING({})[{}]".format(event.pid, event.filename))

    event.close()


@prints_errors
def handle_self_emitted_event(notifier, event):
    if event.open_perm_event or event.access_perm_event:
        allow_event(notifier, event)

    event.close()


if __name__ == '__main__':
    file_stats = PrintableDefaultDict(lambda: {})
    proc_stats = PrintableDefaultDict(lambda: PrintableDefaultDict(lambda: {}))
    loop_events()
