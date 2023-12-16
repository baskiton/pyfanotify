import errno
import os
import select

import pyfanotify as fan
import pysetns as ns


def mark_mounts_target(n):
    for path in '/proc/%s/mounts' % n.target_pid, '/proc/self/mounts':
        try:
            for ln in open(path).readlines():
                fsname, mp, fs_type, opts, freq, passno = ln.split()
                if fsname.startswith('/'):
                    fanot.mark(mp, is_type='mp')
            return
        except IOError:
            pass
    return errno.EAGAIN if (n.namespaces & ns.NS_MNT) else errno.ENOENT


def mark_mounts(pid, namespaces=ns.NS_ALL):
    n = ns.Namespace(pid, namespaces, keep_caps=True)
    n.enter(mark_mounts_target, n)
    if n.errors:
        fanot._debug('NS errors: %s', n.errors)
    return n.retry


def get_mounts():
    mounts = {}
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        try:
            mounts.setdefault(os.readlink('/proc/%s/ns/mnt' % pid), pid)
        except:
            pass
    return mounts


def mounts_upd():
    global _old_mounts

    mounts = get_mounts()
    if mounts != _old_mounts:
        _old_mounts = mounts
        for mnt, pid in mounts.items():
            try:
                if mark_mounts(pid, ns.NS_PID | ns.NS_MNT | ns.NS_USER):
                    mark_mounts(pid, ns.NS_PID | ns.NS_USER)
            except Exception as e:
                fanot._debug('mark_mounts error: %s', e)


if __name__ == '__main__':
    _old_mounts = 0
    mounts_upd_timeout = 10
    fanot = fan.Fanotify(fn=mounts_upd, fn_timeout=mounts_upd_timeout)
    fanot.start()

    cli = fan.FanotifyClient(fanot, path_pattern='*', ev_types=fan.FAN_ACCESS)
    poll = select.poll()
    poll.register(cli.sock.fileno(), select.POLLIN)
    try:
        while poll.poll():
            x = {}
            for i in cli.get_events():
                i.ev_types = fan.evt_to_str(i.ev_types)
                x.setdefault(i.path, []).append(i)
            if x:
                print(x)
    except:
        print('STOP')

    cli.close()
    fanot.stop()
