# coding: utf-8

__all__ = '__version__', 'Fanotify', 'FanotifyClient', 'FanoRule'

import array
import atexit
import datetime
import errno
import hashlib
import logging
import multiprocessing as mp
import os
import socket
import struct
import sys

from typing import Any, Callable, Iterable, Optional, Tuple, Union

from . import ext

FanoRule = ext.FanoRule

__version__ = '0.2.1'

# events
FAN_ACCESS = ext.FAN_ACCESS
FAN_MODIFY = ext.FAN_MODIFY
FAN_ATTRIB = ext.FAN_ATTRIB             # since Linux 5.1
FAN_CLOSE_WRITE = ext.FAN_CLOSE_WRITE
FAN_CLOSE_NOWRITE = ext.FAN_CLOSE_NOWRITE
FAN_OPEN = ext.FAN_OPEN
FAN_MOVED_FROM = ext.FAN_MOVED_FROM     # since Linux 5.1
FAN_MOVED_TO = ext.FAN_MOVED_TO         # since Linux 5.1
FAN_CREATE = ext.FAN_CREATE             # since Linux 5.1
FAN_DELETE = ext.FAN_DELETE             # since Linux 5.1
FAN_DELETE_SELF = ext.FAN_DELETE_SELF   # since Linux 5.1
FAN_MOVE_SELF = ext.FAN_MOVE_SELF       # since Linux 5.1
FAN_OPEN_EXEC = ext.FAN_OPEN_EXEC       # since Linux 5.0

FAN_Q_OVERFLOW = ext.FAN_Q_OVERFLOW

FAN_OPEN_PERM = ext.FAN_OPEN_PERM
FAN_ACCESS_PERM = ext.FAN_ACCESS_PERM
FAN_OPEN_EXEC_PERM = ext.FAN_OPEN_EXEC_PERM  # since Linux 5.0

FAN_RENAME = ext.FAN_RENAME     # since Linux 5.17

FAN_ONDIR = ext.FAN_ONDIR

FAN_EVENT_ON_CHILD = ext.FAN_EVENT_ON_CHILD

FAN_CLOSE = FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE
FAN_MOVE = FAN_MOVED_FROM | FAN_MOVED_TO

FAN_ALL_EVENTS = FAN_ACCESS | FAN_MODIFY | FAN_OPEN | FAN_OPEN_EXEC | FAN_CLOSE | FAN_ONDIR | FAN_EVENT_ON_CHILD
FAN_ALL_PERM_EVENTS = FAN_OPEN_PERM | FAN_ACCESS_PERM | FAN_OPEN_EXEC_PERM
FAN_ALL_FID_EVENTS = (FAN_ATTRIB | FAN_MOVE | FAN_CREATE | FAN_DELETE | FAN_DELETE_SELF
                      | FAN_MOVE_SELF | FAN_RENAME | FAN_ONDIR | FAN_EVENT_ON_CHILD)

# flags for init()
FAN_CLOEXEC = ext.FAN_CLOEXEC
FAN_NONBLOCK = ext.FAN_NONBLOCK

# NOT bitwise flags
FAN_CLASS_NOTIF = ext.FAN_CLASS_NOTIF
FAN_CLASS_CONTENT = ext.FAN_CLASS_CONTENT
FAN_CLASS_PRE_CONTENT = ext.FAN_CLASS_PRE_CONTENT

FAN_UNLIMITED_QUEUE = ext.FAN_UNLIMITED_QUEUE
FAN_UNLIMITED_MARKS = ext.FAN_UNLIMITED_MARKS
FAN_ENABLE_AUDIT = ext.FAN_ENABLE_AUDIT         # since Linux 4.15

# Flags to determine fanotify event format
FAN_REPORT_TID = ext.FAN_REPORT_TID             # since Linux 4.20
FAN_REPORT_FID = ext.FAN_REPORT_FID             # since Linux 5.1
FAN_REPORT_DIR_FID = ext.FAN_REPORT_DIR_FID     # since Linux 5.9
FAN_REPORT_NAME = ext.FAN_REPORT_NAME           # since Linux 5.9

FAN_REPORT_DFID_NAME = ext.FAN_REPORT_DFID_NAME  # since Linux 5.9

# flags for mark()
FAN_MARK_ADD = ext.FAN_MARK_ADD
FAN_MARK_REMOVE = ext.FAN_MARK_REMOVE
FAN_MARK_DONT_FOLLOW = ext.FAN_MARK_DONT_FOLLOW
FAN_MARK_ONLYDIR = ext.FAN_MARK_ONLYDIR
FAN_MARK_IGNORED_MASK = ext.FAN_MARK_IGNORED_MASK
FAN_MARK_IGNORED_SURV_MODIFY = ext.FAN_MARK_IGNORED_SURV_MODIFY
FAN_MARK_FLUSH = ext.FAN_MARK_FLUSH

# NOT bitwise flags
FAN_MARK_INODE = ext.FAN_MARK_INODE
FAN_MARK_MOUNT = ext.FAN_MARK_MOUNT
FAN_MARK_FILESYSTEM = ext.FAN_MARK_FILESYSTEM   # since Linux 4.20

FANOTIFY_METADATA_VERSION = ext.FANOTIFY_METADATA_VERSION

# Legit userspace responses to a _PERM event
FAN_ALLOW = ext.FAN_ALLOW
FAN_DENY = ext.FAN_DENY
FAN_AUDIT = ext.FAN_AUDIT

FAN_NOFD = ext.FAN_NOFD     # No fd set in event
AT_FDCWD = ext.AT_FDCWD

_INIT_FLAGS = FAN_CLOEXEC | FAN_NONBLOCK | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS | FAN_CLASS_CONTENT
_INIT_FID_FLAGS = FAN_REPORT_FID | FAN_REPORT_DFID_NAME
_INIT_O_FLAGS = os.O_RDONLY | os.O_LARGEFILE | ext.O_CLOEXEC | os.O_NOATIME

_CMD_STOP = ext.CMD_STOP
_CMD_CONNECT = ext.CMD_CONNECT
_CMD_DISCONNECT = ext.CMD_DISCONNECT

_EVT_MASKS = {
    FAN_ACCESS: 'access',
    FAN_MODIFY: 'modify',
    FAN_ATTRIB: 'attrib',
    FAN_CLOSE_WRITE: 'close_write',
    FAN_CLOSE_NOWRITE: 'close_nowrite',
    FAN_OPEN: 'open',
    FAN_MOVED_FROM: 'moved_from',
    FAN_MOVED_TO: 'moved_to',
    FAN_CREATE: 'create',
    FAN_DELETE: 'delete',
    FAN_DELETE_SELF: 'delete_self',
    FAN_MOVE_SELF: 'move_self',
    FAN_OPEN_EXEC: 'open_exec',
    FAN_OPEN_PERM: 'open_perm',
    FAN_ACCESS_PERM: 'access_perm',
    FAN_OPEN_EXEC_PERM: 'open_exec_perm',
    FAN_RENAME: 'rename',
    FAN_ONDIR: 'ondir',
    FAN_EVENT_ON_CHILD: 'on_child',

    0: ''
}


class Fanotify(mp.Process):
    """
    Wrapper for Linux fanotify. Runs in a new process.
    """

    def __init__(self, init_fid: bool = False, log: logging.Logger = None,
                 fn: Callable = None, fn_args: Tuple = (), fn_timeout: int = 0):
        """
        :param init_fid: Enable filesystem events to watch (FAN_CREATE, FAN_DELETE, FAN_MOVE, FAN_ATTRIB).
            See **man fanotify_init** for FAN_REPORT_FID
            and FAN_REPORT_DIR_FID
        :param log: Logger
        :param fn: Function that will be called after the specified `fn_timeout`
        :param fn_args: Arguments for `fn`
        :param fn_timeout: Timeout for `fn`

        :raises OSError: if fanotify is not set in kernel or other fanotify
            error (see man fanotify_init)
        :raises TypeError: if `fn` is not callable or `fn_args` is not tuple
        """

        super().__init__(name='Fanotify')
        self._with_fid = init_fid
        self._log = log
        self._ctx = ext.create()

        try:
            ext.mark(self._ctx, FAN_MARK_ADD, FAN_MODIFY | FAN_CLOSE_WRITE | FAN_EVENT_ON_CHILD, AT_FDCWD, '')
        except OSError as e:
            if e.errno != errno.EBADF:
                if e.errno == errno.ENOSYS:
                    self._exception('No fanotify!')
                    e.strerror += ': No fanotify!'
                else:
                    self._exception(f'Fanotify init: {e}')
                raise

        flags = _INIT_FLAGS
        if init_fid:
            flags &= ~FAN_CLASS_CONTENT
            flags |= _INIT_FID_FLAGS

        try:
            self._fd = ext.init(self._ctx, flags, _INIT_O_FLAGS)
        except OSError as e:
            e.strerror = f'Fanotify init: {e.strerror}'
            self._exception(f'{e}')
            raise

        self._rd, self._wr = mp.Pipe(False)
        self._pid = os.getpid()
        self._is_ready = True

        if fn and not callable(fn):
            raise TypeError("'fn' is not callable")
        self._fn = fn
        if not isinstance(fn_args, tuple):
            raise TypeError(f"'fn_args': expected 'tuple', got '{type(fn_args)}' instead.")
        self._fn_args = fn_args
        self._fn_timeout = int(fn_timeout)

    @property
    def with_fid(self) -> bool:
        return self._with_fid

    def start(self) -> None:
        """
        Start Fanotify process
        """

        if self._is_ready:
            self._is_ready = False
            super(Fanotify, self).start()
            atexit.register(lambda x: (x.stop(), x.join()), self)
            self._rd.close()
            self._rd = None

    def run(self) -> None:
        self._debug('start')
        try:
            self._action()
        except BaseException as e:
            self._exception(f'Exception occured: {e}')
        finally:
            self._close()
            self._debug('finish')

    def stop(self) -> None:
        """
        Stop Fanotify process
        """

        if self._wr:
            wr = self._wr
            self._wr = None
            wr.send((_CMD_STOP,))
            wr.close()
        self.join()
        if self._fd != FAN_NOFD:
            os.close(self._fd)
            self._fd = FAN_NOFD

    def connect(self, rule: FanoRule) -> None:
        """
        Add :class:`FanoRule` to receive events on it
        """

        if not isinstance(rule, FanoRule):
            raise TypeError(f'Got {type(rule).__name__}, FanoRule expected')
        self._wr.send((_CMD_CONNECT, rule))

    def disconnect(self, rule: FanoRule) -> None:
        """
        Delete the :class:`FanoRule` so as not to receive events for it
        """

        if not isinstance(rule, FanoRule):
            raise TypeError(f'Got {type(rule).__name__}, FanoRule expected')
        self._wr.send((_CMD_DISCONNECT, rule))

    def mark(self, path: Union[str, Iterable], ev_types: int = FAN_ALL_EVENTS,
             is_type: str = '', dont_follow: bool = False,
             as_ignore: bool = False, remove: bool = False) -> None:
        """
        To detail see **man fanotify_mark**

        Adds, removes, or modifies an fanotify mark on a
        filesystem object. The caller must have read permission on the
        filesystem object that is to be marked.
        `ev_types` must be nonempty

        :param path: path to be marked
        :param ev_types: defines which events shall be listened for (or which
            shall be ignored). It is a bit mask composed values. See man
        :param is_type: type of `path`. It can be:

            - ``'mp'`` - is mount point
            - ``'fs'`` - is filesystem
            - ``'dir'`` - is directory

        :param dont_follow: if `path` is a symbolic link, mark the link itself,
            rather than the file to which it refers.
        :param as_ignore: if `True` add/remove to/from ignore mask.
        :param remove: if `True`, events in `ev_types` will be removed from
            the mark mask (or from ignore mask);
            else events will be added to the mark mask (or to ignore mask).
        """

        if ev_types & (FAN_OPEN_PERM | FAN_ACCESS_PERM | FAN_OPEN_EXEC_PERM):
            msg = 'PERM events are not supported yet'
            self._error(msg)
            raise NotImplementedError(msg)

        if isinstance(path, str):
            flags = (remove and FAN_MARK_REMOVE) or FAN_MARK_ADD

            if is_type == 'mp':
                flags |= FAN_MARK_MOUNT
            elif is_type == 'fs':
                flags |= FAN_MARK_FILESYSTEM
            elif is_type == 'dir':
                flags |= FAN_MARK_ONLYDIR

            if dont_follow:
                flags |= FAN_MARK_DONT_FOLLOW

            if as_ignore:
                flags |= FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORED_SURV_MODIFY

            try:
                ext.mark(self._ctx, flags, ev_types, AT_FDCWD, path)
                # self._debug(f'{path} is marked')
            except OSError as e:
                msg = f'mark(): {e}'
                if e.errno == errno.EBADF:
                    msg += f': fd={self._fd} is not an fanotify descriptor'
                elif e.errno == errno.EINVAL:
                    if self.with_fid and (ev_types & (FAN_OPEN_PERM | FAN_ACCESS_PERM | FAN_OPEN_EXEC_PERM)):
                        msg += ': PERM events are not allowed with FID report'
                    elif ev_types & FAN_ALL_FID_EVENTS:
                        if not self.with_fid:
                            msg += ': Filesystem events required an fanotify FID group (init_fid=True when init)'
                        elif flags & FAN_MARK_MOUNT:
                            msg += ': Filesystem events not supported with mount point'
                    else:
                        msg += f': invalid evt_types or fd={self._fd} is not an fanotify descriptor'
                self._error(msg)
        elif isinstance(path, Iterable):
            for p in path:
                self.mark(p, ev_types, is_type, dont_follow)

    def flush(self, do_non_mounts=True, do_mounts=True, do_fs=True) -> None:
        """
        To detail see **man fanotify_mark** for FAN_MARK_FLUSH

        Remove either all marks for filesystems, all marks for
        mounts, or all marks for directories and files from the
        fanotify group.

        :param do_non_mounts: Remove all marks for directories and files
        :param do_mounts: Remove all marks for mounts
        :param do_fs: Remove all marks for filesystems (since Linux 4.20)
        """

        try:
            if do_non_mounts:
                ext.mark(self._ctx, FAN_MARK_FLUSH, 0, AT_FDCWD)
            if do_mounts:
                ext.mark(self._ctx, FAN_MARK_FLUSH | FAN_MARK_MOUNT, 0, AT_FDCWD)
            if do_fs and FAN_MARK_FILESYSTEM:   # Linux 4.20 and above
                ext.mark(self._ctx, FAN_MARK_FLUSH | FAN_MARK_FILESYSTEM, 0, AT_FDCWD)
        except OSError as e:
            msg = f'flush(): {e}'
            if e.errno == errno.EBADF:
                msg += f': fd={self._fd} is not an fanotify descriptor'
            self._exception(msg)

    def _close(self) -> None:
        self._rd.close()
        self._rd = None

    def _action(self) -> None:
        self._wr.close()
        self._wr = None
        ext.run(self._ctx, self._rd, sys.stdout.fileno(), self._fn, self._fn_args, self._fn_timeout)

    def _debug(self, *args, **kwargs) -> None:
        if self._log:
            self._log.debug(*args, **kwargs)
        else:
            self._do_log('DEBUG', *args, **kwargs)

    def _info(self, *args, **kwargs) -> None:
        if self._log:
            self._log.info(*args, **kwargs)
        else:
            self._do_log('INFO', *args, **kwargs)

    def _warning(self, *args, **kwargs) -> None:
        if self._log:
            self._log.warning(*args, **kwargs)
        else:
            self._do_log('WARNING', *args, **kwargs)

    def _error(self, *args, **kwargs) -> None:
        if self._log:
            self._log.error(*args, **kwargs)
        else:
            self._do_log('ERROR', *args, **kwargs)

    def _critical(self, *args, **kwargs) -> None:
        if self._log:
            self._log.critical(*args, **kwargs)
        else:
            self._do_log('CRITICAL', *args, **kwargs)

    def _exception(self, *args, **kwargs) -> None:
        if self._log:
            self._log.exception(*args, **kwargs)
        else:
            self._do_log('EXCEPTION', *args, **kwargs)

    def _do_log(self, lvl: str, msg: str, *args, **kwargs) -> None:
        x = sys.stdout if (lvl in ('DEBUG', 'INFO')) else sys.stderr
        x.write(f'{datetime.datetime.now()} {lvl}: Fanotify: {msg % args}\n')
        x.flush()


class FanotifyData(dict):
    """
    Contains fanotify event information
    """

    def __init__(self, fd: int = -1, pid: int = 0, ev_types: int = 0,
                 exe: str = None, cwd: str = None, path: str = None):
        """
        :param fd: File descriptor if passed
        :param pid: PID of caused process
        :param ev_types: Event types of fanotify event
        :param exe: EXE of the event caused process if passed
        :param cwd: CWD of the event caused process if passed
        :param path: PATH of the event caused file if passed
        """

        super().__init__(fd=fd, pid=pid, ev_types=ev_types, exe=exe, cwd=cwd, path=path)

    def __getattr__(self, name: str) -> Any:
        return self[name]

    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value

    def __delattr__(self, name: str) -> None:
        del self[name]


class FanotifyClient:
    """
    Client for easy use and getting data via Fanotify.
    """

    _PID_EVT_S = struct.Struct('=qQ')
    _P_SZ_S = struct.Struct('=I')

    def __init__(self, fanotify: Fanotify, **rkw) -> None:
        """
        :param fanotify: :class:`Fanotify` object to associate with it.
        :param dict rkw: Keyword arguments for :class:`FanoRule`, excluding
            :py:attr:`FanoRule.name` - this will be auto-generated and stored
            to :py:attr:`FanotifyClient.rname`
        """

        self.fanotify = fanotify
        self.rname = hashlib.sha256(rkw.pop('name', None) or os.urandom(32)).hexdigest().encode()
        self.rule = FanoRule(name=self.rname, **rkw)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.setblocking(False)
        s.bind(b'\0' + self.rname)
        self.sock = s
        self.fanotify.connect(self.rule)

    def close(self) -> None:
        """
        Close the connection to the Fanotify object. The data will no
        longer be received.
        """

        self.fanotify.disconnect(self.rule)
        self.sock.close()

    def get_events(self) -> FanotifyData:
        """
        Receive fanotify events according to the established rules
        for the current client.
        """

        while 1:
            try:
                data = self._recv_data()
            except (socket.error, OSError):
                break
            if not data:
                break
            yield data

    def _recv_data(self) -> Optional[FanotifyData]:
        msg, anc, flags, addr = self.sock.recvmsg(8192, 4096, socket.MSG_DONTWAIT)
        if not msg:
            return
        res = FanotifyData()
        for level, ty, fd in anc:
            if level == socket.SOL_SOCKET and ty == socket.SCM_RIGHTS:
                fds = array.array('i')
                fds.fromstring(fd)
                res.fd = fds[0]
        res.pid, res.ev_types = self._PID_EVT_S.unpack_from(msg, 0)
        off = self._PID_EVT_S.size
        for i in 'exe', 'cwd', 'path':
            sz, = self._P_SZ_S.unpack_from(msg, off)
            off += self._P_SZ_S.size
            res[i] = msg[off:off + sz]
            off += sz
        return res


def evt_to_str(evt: int):
    return '|'.join(v for k, v in _EVT_MASKS.items() if k & evt)
