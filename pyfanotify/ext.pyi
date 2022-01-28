from multiprocessing.connection import Connection
from typing import AnyStr, Iterable, Tuple, Union, Callable, Any

# events
FAN_ACCESS: int
FAN_MODIFY: int
FAN_ATTRIB: int         # since Linux 5.1
FAN_CLOSE_WRITE: int
FAN_CLOSE_NOWRITE: int
FAN_OPEN: int
FAN_MOVED_FROM: int     # since Linux 5.1
FAN_MOVED_TO: int       # since Linux 5.1
FAN_CREATE: int         # since Linux 5.1
FAN_DELETE: int         # since Linux 5.1
FAN_DELETE_SELF: int    # since Linux 5.1
FAN_MOVE_SELF: int      # since Linux 5.1
FAN_OPEN_EXEC: int      # since Linux 5.0

FAN_Q_OVERFLOW: int

FAN_OPEN_PERM: int
FAN_ACCESS_PERM: int
FAN_OPEN_EXEC_PERM: int # since Linux 5.0

FAN_ONDIR: int

FAN_EVENT_ON_CHILD: int

FAN_CLOSE: int
FAN_MOVE: int

# flags for init()
FAN_CLOEXEC: int
FAN_NONBLOCK: int

# NOT bitwise flags
FAN_CLASS_NOTIF: int
FAN_CLASS_CONTENT: int
FAN_CLASS_PRE_CONTENT: int

FAN_UNLIMITED_QUEUE: int
FAN_UNLIMITED_MARKS: int
FAN_ENABLE_AUDIT: int   # since Linux 4.15

# Flags to determine fanotify event format
FAN_REPORT_TID: int     # since Linux 4.20
FAN_REPORT_FID: int     # since Linux 5.1
FAN_REPORT_DIR_FID: int # since Linux 5.9
FAN_REPORT_NAME: int    # since Linux 5.9

FAN_REPORT_DFID_NAME: int   # since Linux 5.9

# flags for mark()
FAN_MARK_ADD: int
FAN_MARK_REMOVE: int
FAN_MARK_DONT_FOLLOW: int
FAN_MARK_ONLYDIR: int
FAN_MARK_IGNORED_MASK: int
FAN_MARK_IGNORED_SURV_MODIFY: int
FAN_MARK_FLUSH: int

# NOT bitwise flags
FAN_MARK_INODE: int
FAN_MARK_MOUNT: int
FAN_MARK_FILESYSTEM: int    # since Linux 4.20

FANOTIFY_METADATA_VERSION: int

# Legit userspace responses to a _PERM event
FAN_ALLOW: int
FAN_DENY: int
FAN_AUDIT: int

FAN_NOFD: int   # No fd set in event
AT_FDCWD: int

CMD_STOP: int
CMD_CONNECT: int
CMD_DISCONNECT: int

def init(flags: int, o_flags: int) -> int:
    """
    Wrapper for fanotify_init. See manpage for more details:
    https://man7.org/linux/man-pages/man2/fanotify_init.2.html

    Returns:
        int: Fanotify file descriptor

    Raises:
        OSError: Raised when fanotify_init sets errno
    """
    return -1

def mark(fd: int, flags: int, mask: int, dirfd: int, pathname: str = None) -> None:
    """
    Wrapper for fanotify_mark. See manpage for more details:
    https://man7.org/linux/man-pages/man2/fanotify_mark.2.html

    Raise
        OSError: Raised when fanotify_mark sets errno
    """
    return

def run(fd: int, rcon: Connection, log_fd: int = None, fn: Callable = None, fn_args: Tuple = None, fn_timeout: int = 0) -> None:
    """
    Main routine. If the event matches the rule, information about the event
    will be sent to the unix socket named `"\\\\0 + rule.name"`
    (the socket with the corresponding name must be open!):
     * fd: if `rule.pass_fd` is `True`, this is an open file descriptor for event object;
     * exe: exe of `pid`, if the rules was matched using `rule.exe_pattern`; otherwise empty string;
     * cwd: cwd of `pid`, if the rules was matched using `rule.cwd_pattern`; otherwise empty string;
     * path: path of `fd`, if the rules was matched using `rule.path_pattern`; otherwise empty string;

    Args:
        fd (int): Fanotify file descriptor.
        rcon (Connection): Connection for read commands.
        log_fd (int): Optionally. Logger file descriptor.
            Message format:
                uint32_t msg_len;
                char msg[];
        fn (Callable): Optionally. Function to call at each iteration.
        fn_args (tuple): Optionally. Arguments for fn.
        fn_timeout (int): Optionally. Timeout in seconds between fn calls.

    Raises:
        AssertionError: When fanotify metadata version is mismatch
        OSError: Some errors
    """
    return

# def response(fd: int, response: int) -> bytes: ...


class FanoRule:
    """
    Rule for fanotify

    Attributes:
        name (str|bytes): Name of rule
        pids (list|tuple|set): PIDS
        ev_types (int): Event types mask
        exe_pattern (str): exe
        cwd_pattern (str): cwd
        path_pattern (str): path
        pass_fd (bool): Pass file descriptor
    """

    def __init__(
            self,
            name: AnyStr,
            pids: Iterable[Union[int, AnyStr]] = None,
            ev_types: int = 0,
            exe_pattern: AnyStr = None,
            cwd_pattern: AnyStr = None,
            path_pattern: AnyStr = None,
            pass_fd: bool = False
    ) -> None:
        """
        Args:
            name (str|bytes): Name of rule
            pids (list|tuple|set): PIDS
            ev_types (int): Event types mask
            exe_pattern (str): exe
            cwd_pattern (str): cwd
            path_pattern (str): path
            pass_fd (bool): Pass file descriptor
        """
        return

    @property
    def name(self) -> AnyStr: ...
    @property
    def pids(self) -> Iterable[Union[int, AnyStr]]: ...
    @property
    def ev_types(self) -> int: ...
    @property
    def exe_pattern(self) -> AnyStr: ...
    @property
    def cwd_pattern(self) -> AnyStr: ...
    @property
    def path_pattern(self) -> AnyStr: ...
    @property
    def pass_fd(self) -> bool: ...
