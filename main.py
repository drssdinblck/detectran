import argparse
import os.path
from time import sleep
from concurrent.futures import ThreadPoolExecutor
from my_utils import (
    PrintableDefaultDict, est_entropy, is_encrypting,
    prints_events, prints_errors,
    deploy_honeypots, remove_honeypots
)

from butter_helper import *


def monitor_dir_and_loop_events(directory_path, honeypot_paths=()):
    self_event_worker = ThreadPoolExecutor(4)
    ext_event_worker = ThreadPoolExecutor(1)
    honeypot_event_worker = ThreadPoolExecutor(1)

    notifier = Fanotify(FAN_CLASS_CONTENT)
    mask = FAN_MODIFY | FAN_EVENT_ON_CHILD | FAN_OPEN_PERM | FAN_ACCESS_PERM
    notifier.watch(directory_path, mask)

    for event in notifier:
        if event.pid == os.getpid():
            self_event_worker.submit(handle_self_emitted_event, notifier, event)
        else:
            if event.filename in honeypot_paths:
                honeypot_event_worker.submit(handle_honeypot_event, notifier, event)
            else:
                ext_event_worker.submit(handle_external_event, notifier, event)

    notifier.close()


@prints_errors
def handle_honeypot_event(notifier, event):
    if not event.open_perm_event and not event.access_perm_event:
        event.close()
        return

    if proc_stats[event.pid]['is_trusted']:
        allow_event(notifier, event)
    else:
        print("HONEYPOT_TOUCH_EVENT({}){{}}[{}]".format(event.pid, proc_stats[event.pid], event.filename))
        proc_stats[event.pid]['is_trusted'] = decide_trust_process(notifier, event)

    event.close()


@prints_errors
def handle_external_event(notifier, event):
    if event.open_perm_event or event.access_perm_event:
        if event.filename not in file_stats:
            file_stats[event.filename]['ent'] = est_entropy(event)

        if proc_stats[event.pid]['is_trusted']:
            allow_event(notifier, event)
        elif proc_stats[event.pid]['suspicious_activity_count'] < 3:
            allow_event(notifier, event)
        else:
            print("SUSPICIOUS_PROCESS_EVENT({})[{}]".format(event.pid, proc_stats[event.pid]))
            proc_stats[event.pid]['is_trusted'] = decide_trust_process(notifier, event)
    elif event.modify_event:
        ent_before = file_stats[event.filename]['ent']
        ent_after = est_entropy(event)
        proc_stats[event.pid]['file_activity'][event.filename]['ent_before'] = ent_before
        proc_stats[event.pid]['file_activity'][event.filename]['ent_after'] = ent_after
        file_stats[event.filename]['ent'] = ent_after

        if is_encrypting(ent_before, ent_after):
            proc_stats[event.pid]['suspicious_activity_count'] += 1

    event.close()


@prints_errors
def handle_self_emitted_event(notifier, event):
    if event.open_perm_event or event.access_perm_event:
        allow_event(notifier, event)

    event.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='detectran - a behavioral ransomware protector'
    )

    parser.add_argument(
        '--no-honeypots', '-n',
        action='store_true',
        help='deactivate deployment of honeypots'
    )

    args = parser.parse_args()

    monitor_dir = os.path.expanduser('/home/appsec/Testfanotify')
    file_stats = PrintableDefaultDict(lambda: {})
    proc_stats = PrintableDefaultDict(
        lambda: {
            'is_trusted': False,
            'suspicious_activity_count': 0,
            'file_activity': PrintableDefaultDict(lambda: {})
        }
    )

    honeypots = []
    try:
        if not args.no_honeypots:
            honeypots = deploy_honeypots(monitor_dir)

        sleep(1)
        monitor_dir_and_loop_events(monitor_dir, honeypots)
    finally:
        remove_honeypots(honeypots)
