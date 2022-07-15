#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif  // _GNU_SOURCE

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <structmember.h>

#include <fcntl.h>
#include <fnmatch.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>


PyDoc_STRVAR(ext__doc__,
"Wrapper for fanotify.\n"
"\n"
"See fanotify manpage for more details:\n"
"    https://man7.org/linux/man-pages/man7/fanotify.7.html\n");

#define CMD_STOP 0
#define CMD_CONNECT 1
#define CMD_DISCONNECT 2

#if (EAGAIN == EWOULDBLOCK)
#define AGAIN (errno == EAGAIN)
#else
#define AGAIN (errno == EAGAIN || errno == EWOULDBLOCK)
#endif

#define O_FLAGS (O_RDONLY|O_LARGEFILE|O_CLOEXEC|O_NOATIME)

typedef struct str_val {
    uint32_t len;
    char buf[PATH_MAX];
} str_val_t;

struct c_rule {
    struct c_rule *next;
    ssize_t hash;
    unsigned long ev_types;
    size_t pids_cnt;
    pid_t *pids;
    str_val_t name;
    str_val_t exe_pattern;
    str_val_t cwd_pattern;
    str_val_t path_pattern;
    unsigned char pass_fd;
};

typedef struct {
    PyObject_HEAD;
    Py_buffer name;
    Py_buffer exe_pattern;
    Py_buffer cwd_pattern;
    Py_buffer path_pattern;
    PyObject *pids;
    unsigned long ev_types;
    unsigned char pass_fd;
} ext_FanoRule;

#define FANO_RULE_SET_FIELD_VAL(field, val) ({  \
        PyObject *tmp = self->field;            \
        Py_INCREF(val);                         \
        self->field = val;                      \
        Py_XDECREF(tmp);                        \
})

#define FANO_RULE_SET_FIELD(x) FANO_RULE_SET_FIELD_VAL(x, x)

#define FANO_RULE_DECREFS(rule) ({                \
        PyBuffer_Release(&(rule)->name);          \
        PyBuffer_Release(&(rule)->exe_pattern);   \
        PyBuffer_Release(&(rule)->cwd_pattern);   \
        PyBuffer_Release(&(rule)->path_pattern);  \
        Py_CLEAR((rule)->pids);                   \
        (rule)->ev_types = 0;                     \
        (rule)->pass_fd = 0;                      \
})

#define RULE_FIELD_INIT(x) ({           \
        if (rule->x.len) {              \
            memcpy(new->x.buf,          \
                   rule->x.buf,         \
                   rule->x.len);        \
            new->x.len = rule->x.len;   \
        }                               \
})

static void
rules_list_add(struct c_rule **rules, ext_FanoRule *rule)
{
    ssize_t hash = PyObject_Hash(rule->name.obj);
    while (*rules) {
        if (hash == (*rules)->hash)
            return;
        rules = &(*rules)->next;
    }
    struct c_rule *new;
    if (!(new = PyMem_Malloc(sizeof(*new))))
        return;

    memset(new, 0, sizeof(*new));
    new->hash = hash;
    new->pass_fd = rule->pass_fd;
    new->ev_types = rule->ev_types;
    RULE_FIELD_INIT(name);
    RULE_FIELD_INIT(exe_pattern);
    RULE_FIELD_INIT(cwd_pattern);
    RULE_FIELD_INIT(path_pattern);

    Py_ssize_t pid_cnt = PySequence_Size(rule->pids);
    if (pid_cnt > 0) {
        if (!(new->pids = PyMem_Malloc(pid_cnt * sizeof(*new->pids)))) {
            PyMem_Free(new);
            return;
        }
        new->pids_cnt = pid_cnt;
        PyObject *iter = PyObject_GetIter(rule->pids);
        PyObject *py_item = PyIter_Next(iter);
        for (int i = 0; py_item && i < pid_cnt; ++i) {
            new->pids[i] = (pid_t)PyLong_AsLong(py_item);
            Py_DECREF(py_item);
            py_item = PyIter_Next(iter);
        }
        Py_DECREF(iter);
    }
    *rules = new;
}

static void
rules_list_raw_del(struct c_rule **rules, long hash)
{
    while (*rules) {
        if (hash == (*rules)->hash) {
            struct c_rule *next = (*rules)->next;
            PyMem_Free((*rules)->pids);
            PyMem_Free(*rules);
            *rules = next;
            return;
        }
        rules = &(*rules)->next;
    }
}

static void
rules_list_del(struct c_rule **rules, ext_FanoRule *rule)
{
    rules_list_raw_del(rules, PyObject_Hash(rule->name.obj));
}

static void
rules_list_clear(struct c_rule **rules)
{
    struct c_rule *item = *rules;
    while (item) {
        struct c_rule *next = item->next;
        PyMem_Free(item->pids);
        PyMem_Free(item);
        item = next;
    }
    *rules = 0;
}

static unsigned char
rule_pids_check(struct c_rule *rule, pid_t pid)
{
    if (rule->pids) {
        for (size_t i = 0; i < rule->pids_cnt; ++i)
            if (rule->pids[i] == pid)
                return 0;
        return 1;
    }
    return 0;
}

PyDoc_STRVAR(FanoRule__doc__,
"FanoRule(name, pids=(), ev_types=0, exe_pattern=None, cwd_pattern=None, path_pattern=None, pass_fd=False)\n"
"\n"
"Rule to receive events on it via fanotify. At least one rule parameter\n"
"must be specified (other than the required `name` and optional `pass_fd`)\n"
"\n"
"Args:\n"
"    name (AnyStr): Name of rule\n"
"    pids (Iterable[Union[int, AnyStr]]): PIDS\n"
"    ev_types (int): Event types mask\n"
"    exe_pattern (AnyStr): exe\n"
"    cwd_pattern (AnyStr): cwd\n"
"    path_pattern (AnyStr): path\n"
"    pass_fd (bool): Pass file descriptor\n"
"\n"
"Raises:\n"
"    TypeError: if `pids` is not a set, list or tuple\n"
"    ValueError: if no one rule parameter are specified\n");

static int
FanoRule_init(ext_FanoRule *self, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = {"name", "pids", "ev_types",
                             "exe_pattern", "cwd_pattern", "path_pattern",
                             "pass_fd", NULL};
    PyObject *pids = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "y*|Okz*z*z*b", kwlist,
                                     &self->name, &pids, &self->ev_types,
                                     &self->exe_pattern, &self->cwd_pattern, &self->path_pattern,
                                     &self->pass_fd))
        return -1;

    if (pids && pids != Py_None) {
        if (PySet_Check(pids) || PyList_Check(pids) || PyTuple_Check(pids))
            FANO_RULE_SET_FIELD(pids);
        else {
            PyErr_Format(PyExc_TypeError,
                         "pids must be 'set', 'list' or 'tuple', not '%.200s'",
                         Py_TYPE(pids)->tp_name);
            return -1;
        }
    } else
        FANO_RULE_SET_FIELD_VAL(pids, PyTuple_New(0));

    if (!(PyObject_IsTrue(self->pids)
          || self->ev_types
          || (self->exe_pattern.obj && PyObject_IsTrue(self->exe_pattern.obj))
          || (self->cwd_pattern.obj && PyObject_IsTrue(self->cwd_pattern.obj))
          || (self->path_pattern.obj && PyObject_IsTrue(self->path_pattern.obj)))) {
        PyErr_SetString(PyExc_ValueError, "No rule specified");
        return -1;
    }

    return 0;
}

static void
FanoRule_dealloc(ext_FanoRule *self)
{
    FANO_RULE_DECREFS(self);
    Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *
FanoRule__getstate__(ext_FanoRule *self)
{
    return Py_BuildValue(
        "{sO sO sk sO sO sO sB}",
        "name", self->name.obj,
        "pids", self->pids,
        "ev_types", self->ev_types,
        "exe_pattern", self->exe_pattern.obj ?: Py_None,
        "cwd_pattern", self->cwd_pattern.obj ?: Py_None,
        "path_pattern", self->path_pattern.obj ?: Py_None,
        "pass_fd", self->pass_fd);
}

static PyObject *
FanoRule__setstate__(ext_FanoRule *self, PyObject *state)
{
    static char *kwlist[] = {"name", "pids", "ev_types",
                             "exe_pattern", "cwd_pattern", "path_pattern",
                             "pass_fd", 0};

    FANO_RULE_DECREFS(self);
    PyObject *noargs = PyTuple_New(0);
    if (!PyArg_ParseTupleAndKeywords(
            noargs, state, "y*Okz*z*z*b", kwlist,
            &self->name, &self->pids, &self->ev_types,
            &self->exe_pattern, &self->cwd_pattern, &self->path_pattern,
            &self->pass_fd))
        return 0;

    Py_DECREF(noargs);
    Py_INCREF(self->pids);

    Py_RETURN_NONE;
}

static struct PyMemberDef FanoRule_members[] = {
    {"name", T_OBJECT_EX, offsetof(ext_FanoRule, name.obj), READONLY, "Name of rule"},
    {"pids", T_OBJECT, offsetof(ext_FanoRule, pids), READONLY, "Tuple of pids"},
    {"ev_types", T_ULONG, offsetof(ext_FanoRule, ev_types), READONLY, "Event types"},
    {"exe_pattern", T_OBJECT, offsetof(ext_FanoRule, exe_pattern.obj), READONLY, "EXE pattern"},
    {"cwd_pattern", T_OBJECT, offsetof(ext_FanoRule, cwd_pattern.obj), READONLY, "CWD pattern"},
    {"path_pattern", T_OBJECT, offsetof(ext_FanoRule, path_pattern.obj), READONLY, "PATH pattern"},
    {"pass_fd", T_BOOL, offsetof(ext_FanoRule, pass_fd), READONLY, "Pass sending file descriptor"},
    {NULL}
};

static PyMethodDef FanoRule_methods[] = {
    {"__getstate__", (PyCFunction)FanoRule__getstate__, METH_NOARGS, "Serialize FanoRule"},
    {"__setstate__", (PyCFunction)FanoRule__setstate__, METH_O, "Deserialize FanoRule"},
    {NULL}
};

static PyTypeObject ext_FanoRuleType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "pyfanotify.ext.FanoRule",
    .tp_doc = FanoRule__doc__,
    .tp_basicsize = sizeof(ext_FanoRule),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = PyType_GenericNew,
    .tp_init = (initproc)FanoRule_init,
    .tp_dealloc = (destructor)FanoRule_dealloc,
    .tp_members = FanoRule_members,
    .tp_methods = FanoRule_methods,
};

PyDoc_STRVAR(init__doc__,
"init(flags: int, o_flags: int) -> int\n"
"\n"
"Wrapper for fanotify_init\n"
"\n"
"See manpage for more details:\n"
"    https://man7.org/linux/man-pages/man2/fanotify_init.2.html\n"
"\n"
"Returns:\n"
"    int: Fanotify file descriptor\n"
"\n"
"Raises:\n"
"    OSError: Raised when fanotify_init sets errno\n");

static PyObject *
pyfanotify_init(PyObject *self, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = {"flags", "o_flags", NULL};
    unsigned int flags, o_flags = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "II:init", kwlist,
                                     &flags, &o_flags))
        return NULL;

    int fd = fanotify_init(flags, o_flags);
    if (fd == -1)
        return PyErr_SetFromErrno(PyExc_OSError);

    return PyLong_FromLong(fd);
}

PyDoc_STRVAR(mark__doc__,
"mark(fd: int, flags: int, mask: int, dirfd: int, pathname: str = None) -> None\n"
"\n"
"Wrapper for fanotify_mark\n"
"\n"
"See manpage for more details:\n"
"    https://man7.org/linux/man-pages/man2/fanotify_mark.2.html\n"
"\n"
"Raises:"
"    OSError: Raised when fanotify_mark sets errno\n");

static PyObject *
pyfanotify_mark(PyObject *self, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = {"fd", "flags", "mask", "dirfd", "pathname", NULL};
    int fanotify_fd = -1;
    unsigned int flags = 0;
    uint64_t mask = 0;
    int dirfd = -1;
    const char *pathname = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "iIKi|z:mark", kwlist,
                                     &fanotify_fd, &flags, &mask, &dirfd, &pathname))
        return NULL;

    int err = fanotify_mark(fanotify_fd, flags, mask, dirfd, pathname);
    if (err == -1) {
        if (pathname)
            return PyErr_SetFromErrnoWithFilename(PyExc_OSError, pathname);
        else
            return PyErr_SetFromErrno(PyExc_OSError);
    }

    Py_RETURN_NONE;
}

static ssize_t
do_write(int fd, const void *data, size_t len)
{
    ssize_t ret;
    do {
        ret = write(fd, data, len);
    } while (ret < 0 && errno == EINTR);
    fsync(fd);
    return ret;
}

static void
do_log(int fd, const char *fmt, ...)
{
    if (fd < 0)
        return;

    char msg[4096];
    uint32_t len;
    const int hdr_len = sizeof(len);

    va_list args;
    va_start(args, fmt);
    len = vsnprintf(msg + hdr_len, sizeof(msg) - hdr_len, fmt, args);
    va_end(args);

    if (len <= 0)
        return;
    if (len > sizeof(msg) - hdr_len)
        len = sizeof(msg) - hdr_len;
    *(uint32_t *)msg = len;
    do_write(fd, &msg, len + hdr_len);
}

static int
send_data(int sk_fd, struct c_rule *rule, const struct fanotify_event_metadata *ev,
          str_val_t *exe, str_val_t *cwd, str_val_t *path)
{
    struct {
        int64_t pid;
        uint64_t ev_types;
    } data = {ev->pid, ev->mask};
    struct iovec iov[] = {
        {&data, sizeof(data)},
        {exe, exe->len + sizeof(exe->len)},
        {cwd, cwd->len + sizeof(exe->len)},
        {path, path->len + sizeof(exe->len)},
    };
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    addr.sun_path[0] = '\0';

    memcpy(addr.sun_path + 1, rule->name.buf, rule->name.len);
    struct msghdr msg = {
        .msg_name = &addr,
        .msg_namelen = rule->name.len + offsetof(struct sockaddr_un, sun_path) + 1,
        .msg_flags = 0,
        .msg_iov = iov,
        .msg_iovlen = sizeof(iov) / sizeof(*iov),
    };
    struct __attribute__((packed)) {
        struct cmsghdr cm;
        int fd;
    } cmsg;
    if (rule->pass_fd && ev->fd >= 0) {
        cmsg.cm.cmsg_len = sizeof(cmsg);
        cmsg.cm.cmsg_level = SOL_SOCKET;
        cmsg.cm.cmsg_type = SCM_RIGHTS;
        cmsg.fd = ev->fd;
        msg.msg_control = &cmsg;
        msg.msg_controllen = sizeof(cmsg);
    }
    for (int i = 0; i < 3; ++i) {
        if (sendmsg(sk_fd, &msg, 0) < 0) {
            if (AGAIN)
                usleep(250000);
            else if (errno != EINTR)
                return errno;
            continue;
        }
        break;
    }
    return 0;
}

static ssize_t
get_proc_str(const char *fmt, int meta, char *buf, size_t buf_size)
{
    ssize_t path_len;
    char pathname[32];
    snprintf(pathname, sizeof(pathname) - 1, fmt, meta);
    if ((path_len = readlink(pathname, buf, buf_size - 1)) < 0)
        return 0;
    buf[path_len] = '\0';
    return path_len;
}

#define FIND_RULE_CHECK_MATCH(name, fmt, meta) ({           \
        if (rule->name##_pattern.len) {                     \
            if (!((name).buf[0]) &&                         \
                !((name).len = get_proc_str(fmt, ev->meta,  \
                        (name).buf, sizeof((name).buf))))   \
                goto rules_cycle_continue;                  \
            if (fnmatch(rule->name##_pattern.buf,           \
                        (name).buf, FNM_EXTMATCH))          \
                goto rules_cycle_continue;                  \
        }                                                   \
})

static int
handle_events(int fd, struct c_rule **rules, int sk_fd, int log_fd)
{
    uint8_t buf[8192];
    struct fanotify_event_metadata *ev = (void *)buf;
    ssize_t len;
    str_val_t exe, cwd, path, evt;
    int sk_res;

    struct fanotify_event_info_header *finfo;
    struct fanotify_event_info_fid *fid;
//    struct fanotify_event_info_pidfd *pidfd;
//    struct fanotify_event_info_error *ierror;
    struct file_handle *file_handle;
    const char *file_name;
    ssize_t info_len;

    if ((len = read(fd, buf, sizeof(buf))) == -1)
        return errno;

    while (FAN_EVENT_OK(ev, len)) {
        if (ev->vers != FANOTIFY_METADATA_VERSION)
            return -101;

        exe.buf[0] = cwd.buf[0] = path.buf[0] = evt.buf[0] = '\0';
        exe.len = cwd.len = path.len = evt.len = 0;

#ifdef FAN_REPORT_FID
        if (ev->event_len != FAN_EVENT_METADATA_LEN) {
            info_len = ev->event_len - ev->metadata_len;
            ssize_t rest = info_len;
            int ffd = FAN_NOFD, dfd = FAN_NOFD, *_fd = NULL;
            finfo = (struct fanotify_event_info_header *)(ev + 1);
            file_name = NULL;
            file_handle = NULL;

            while (rest) {
                switch (finfo->info_type) {
                case FAN_EVENT_INFO_TYPE_FID:
# ifdef FAN_REPORT_DIR_FID
                case FAN_EVENT_INFO_TYPE_DFID:
                case FAN_EVENT_INFO_TYPE_DFID_NAME:
# endif // FAN_REPORT_DIR_FID
                    fid = (struct fanotify_event_info_fid *)finfo;
                    file_handle = (struct file_handle *)fid->handle;
                    break;
//                case FAN_EVENT_INFO_TYPE_PIDFD:
//                    pidfd = (struct fanotify_event_info_pidfd *)finfo;
//                    break;
//                case FAN_EVENT_INFO_TYPE_ERROR:
//                    ierror = (struct fanotify_event_info_error *)finfo;
//                    break;
                default:
//                    do_log(log_fd, "Fanotify: invalid info_type: %d\n\n", finfo->info_type);
                    close(ffd);
                    close(dfd);
                    goto evt_end;
                }
# ifdef FAN_REPORT_DIR_FID
                if (finfo->info_type == FAN_EVENT_INFO_TYPE_DFID_NAME)
                    file_name = (char *)(file_handle->f_handle + file_handle->handle_bytes);
# endif // FAN_REPORT_DIR_FID

                if (ev->mask & (FAN_CREATE|FAN_DELETE|FAN_MOVE))
                    _fd = &dfd;
                else if (finfo->info_type == FAN_EVENT_INFO_TYPE_FID)
                    _fd = &ffd;
                else
                    _fd = &dfd;

                if (file_handle) {
                    int evt_fd = open_by_handle_at(AT_FDCWD, file_handle, O_FLAGS);
                    if ((evt_fd == FAN_NOFD) && (errno == ESTALE))
                        goto info_next;
                    close(*_fd);
                    *_fd = evt_fd;
                }
            info_next:
                rest -= finfo->len;
                finfo = (struct fanotify_event_info_header *)((uint8_t *)finfo + finfo->len);
            }

            if (ffd != FAN_NOFD) {
                ev->fd = ffd;
                close(dfd);
                dfd = -1;
            } else if (dfd != FAN_NOFD) {
                if (file_name && !(ev->mask & (FAN_CREATE|FAN_DELETE|FAN_MOVE))) {
                    ev->fd = openat(dfd, file_name, O_FLAGS);
                    if (ev->fd == FAN_NOFD)
                        ev->fd = dfd;
                    else {
                        close(dfd);
                        dfd = FAN_NOFD;
                    }
                } else
                    ev->fd = dfd;
                if (file_name && ev->fd == dfd) {
                    path.len = get_proc_str("/proc/self/fd/%d", dfd, path.buf, sizeof(path.buf));
                    path.buf[path.len] = '/';
                    path.len = stpncpy(path.buf + path.len + 1, file_name, sizeof(path.buf) - path.len - 1) - path.buf;
                }
            } else
                goto evt_end;
        }
#endif // FAN_REPORT_FID

        for (struct c_rule *rule = *rules; rule;) {
            if (rule_pids_check(rule, ev->pid))
                goto rules_cycle_continue;
            if (rule->ev_types && !(rule->ev_types & ev->mask))
                goto rules_cycle_continue;

            FIND_RULE_CHECK_MATCH(exe, "/proc/%d/exe", pid);
            FIND_RULE_CHECK_MATCH(cwd, "/proc/%d/cwd", pid);
            FIND_RULE_CHECK_MATCH(path, "/proc/self/fd/%d", fd);

            if ((sk_res = send_data(sk_fd, rule, ev, &exe, &cwd, &path))) {
                do_log(log_fd, "Fanotify: send_data error for %s: %s",
                       rule->name.buf, strerror(sk_res));
                if (sk_res == ECONNREFUSED) {
                    do_log(log_fd, "Fanotify: delete \"%s\"", rule->name.buf);
                    struct c_rule *to_del = rule;
                    rule = rule->next;
                    rules_list_raw_del(rules, to_del->hash);
                    continue;
                }
            }

        rules_cycle_continue:
            rule = rule->next;
        }

    evt_end:
        close(ev->fd);

        ev = FAN_EVENT_NEXT(ev, len);
    }
    return 0;
}

PyDoc_STRVAR(run__doc__,
"run(fd: int, rcon: Connection[, log_fd: int, fn, fn_args, fn_timeout=0]) -> None\n"
"\n"
"Main routine. If the event matches the rule, information about the event\n"
"will be sent to the unix socket named \"\\0\" + rule.name\n"
"(the socket with the corresponding name must be open!):\n"
"    fd: if 'rule.pass_fd' is True, this is an open file descriptor\n"
"        for event object;\n"
"    exe: exe of pid, if the rules was matched using 'rule.exe_pattern';\n"
"        otherwise empty string;\n"
"    cwd: cwd of pid, if the rules was matched using 'rule.cwd_pattern';\n"
"        otherwise empty string;\n"
"    path: path of fd, if the rules was matched using 'rule.path_pattern';\n"
"        otherwise empty string;\n"
"\n"
"Args:\n"
"    fd (int): Fanotify file descriptor.\n"
"    rcon (Connection): Connection for read commands.\n"
"    log_fd (int): Optionally. Logger file descriptor.\n"
"        Message format:\n"
"            uint32_t msg_len;\n"
"            char msg[];\n"
"    fn (Callable): Optionally. Function to call at each iteration.\n"
"    fn_args (tuple): Optionally. Arguments for fn.\n"
"    fn_timeout (int): Optionally. Timeout in seconds between fn calls.\n"
"\n"
"Raises:\n"
"    AssertionError: When fanotify metadata version is mismatch\n"
"    OSError: Some errors\n");

static PyObject *
pyfanotify_run(PyObject *self, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = {"fd", "rcon", "log_fd",
                             "fn", "fn_args", "fn_timeout", 0};
    int fd, rfd = -1, log_fd = -1, err = 0, sk = -1;
    time_t fn_timeout = 0;
    pid_t ppid = getppid();
    struct c_rule *rules = NULL;
    PyObject *rcon, *tmp = NULL, *fn = NULL, *fn_args = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "iO|iOOl:run", kwlist,
                                     &fd, &rcon, &log_fd, &fn, &fn_args, &fn_timeout))
        return 0;

    if (fd < 0) {
        err = errno = EBADF;
        fn = fn_args = 0;
        goto end;
    }
    if (fn_timeout < 0) {
        PyErr_SetString(PyExc_ValueError, "timeout must be non-negative");
        err = -100;
        fn = fn_args = 0;
        goto end;
    }
    if (PyObject_IsTrue(fn) > 0) {
        if (PyCallable_Check(fn)) {
            Py_INCREF(fn);
        } else {
            fn = fn_args = NULL;
            err = -100;
            PyErr_Format(PyExc_TypeError, "'%.200s' object is not callable",
                         fn->ob_type->tp_name);
            goto end;
        }
    }
    if (fn_args)
        Py_INCREF(fn_args);
    else
        fn_args = PyTuple_New(0);

    if (!((tmp = PyObject_CallMethod(rcon, "fileno", NULL))
            && ((rfd = (int)PyLong_AsLong(tmp)) >= 0))) {
        Py_XDECREF(tmp);
        err = -100;
        goto end;
    }
    Py_XDECREF(tmp);
    tmp = NULL;

    struct pollfd fds[] = {
        {rfd, POLLIN, 0},
        {fd, POLLIN, 0},
    };

    if ((sk = socket(PF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0)) == -1) {
        err = errno;
        goto end;
    }

    time_t fn_timer = 0;
    PyThreadState *state = PyEval_SaveThread();
    while (ppid == getppid()) {
        do {
            if (rules && fn) {
                if (fn_timeout) {
                    time_t tmp_time = time(0);
                    if (tmp_time - fn_timer < fn_timeout)
                        break;
                    fn_timer = tmp_time;
                }
                PyEval_RestoreThread(state);
                Py_DecRef(PyObject_Call(fn, fn_args, 0));
                PyErr_Clear();
                state = PyEval_SaveThread();
            }
        } while (0);

        int rdy = poll(fds, sizeof(fds) / sizeof(*fds), 1000);
        if (rdy < 0) {
            if (errno == EINTR)
                continue;
            err = errno;
            break;
        } else if (!rdy)
            continue;

        if (fds[0].revents & POLLIN) {
            struct c_rule *old = rules;
            PyEval_RestoreThread(state);

            int cmd;
            PyObject *val = NULL;
            if (!((tmp = PyObject_CallMethod(rcon, "recv", NULL))
                    && PyArg_ParseTuple(tmp, "i|O", &cmd, &val))) {
                Py_XDECREF(tmp);
                err = -100;
                goto end;
            }
            switch (cmd) {
            case CMD_STOP:
                Py_XDECREF(tmp);
                err = 0;
                goto end;
            case CMD_CONNECT:
                rules_list_add(&rules, (void *)val);
                break;
            case CMD_DISCONNECT:
                rules_list_del(&rules, (void *)val);
            default:
                break;
            }
            Py_XDECREF(tmp);

            state = PyEval_SaveThread();
            if (!old && rules)
                fn_timer = 0;
            else if (old && !rules) {   // flush
                fanotify_mark(fd, FAN_MARK_FLUSH, 0, AT_FDCWD, 0);
                fanotify_mark(fd, FAN_MARK_FLUSH|FAN_MARK_MOUNT, 0, AT_FDCWD, 0);
            }

        } else if (fds[0].revents & POLLNVAL) {
            err = errno = EBADF;
            break;
        }

        if (fds[1].revents & POLLIN) {
            if ((err = handle_events(fds[1].fd, &rules, sk, log_fd)))
                break;
        } else if (fds[1].revents & POLLNVAL) {
            err = errno = EBADF;
            break;
        }
    }
    PyEval_RestoreThread(state);

end:
    close(sk);
    rules_list_clear(&rules);
    Py_XDECREF(fn);
    Py_XDECREF(fn_args);
    switch (err) {
        case 0:
            Py_RETURN_NONE;
        case -101:
            PyErr_SetString(PyExc_AssertionError, "Mismatch of fanotify metadata version.");
            return 0;
        default:
            errno = err;
            PyErr_SetFromErrno(PyExc_OSError);
        case -100:
            return 0;
    }
}

//PyDoc_STRVAR(response__doc__,
//"response(fd: int, response: int) -> bytes\n"
//"\n");
//
//static PyObject *
//Py(PyObject *self, PyObject *args, PyObject *kwargs)
//{
//    Py_RETURN_NONE;
//}


static PyMethodDef ext_methods[] = {
    {"init", (PyCFunction)pyfanotify_init, METH_VARARGS | METH_KEYWORDS, init__doc__},
    {"mark", (PyCFunction)pyfanotify_mark, METH_VARARGS | METH_KEYWORDS, mark__doc__},
    {"run", (PyCFunction)pyfanotify_run, METH_VARARGS | METH_KEYWORDS, run__doc__},
//        {"response", (PyCFunction)pyfanotify_response, METH_VARARGS | METH_KEYWORDS, response__doc__},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    .m_name = "ext",
    .m_doc = ext__doc__,
    .m_size = -1,
    .m_methods = ext_methods,
};

PyMODINIT_FUNC
PyInit_ext(void)
{
    if (PyType_Ready(&ext_FanoRuleType) < 0)
        return NULL;

    PyObject *module = PyModule_Create(&moduledef);
    if (module == NULL)
        return NULL;

    Py_INCREF(&ext_FanoRuleType);
    if (PyModule_AddObject(module, "FanoRule", (PyObject *)&ext_FanoRuleType) < 0) {
        Py_DECREF(&ext_FanoRuleType);
        Py_DECREF(module);
        return NULL;
    }

    // common
    PyModule_AddIntMacro(module, FAN_ACCESS);
    PyModule_AddIntMacro(module, FAN_MODIFY);
    PyModule_AddIntMacro(module, FAN_CLOSE_WRITE);
    PyModule_AddIntMacro(module, FAN_CLOSE_NOWRITE);
    PyModule_AddIntMacro(module, FAN_OPEN);
    PyModule_AddIntMacro(module, FAN_Q_OVERFLOW);
    PyModule_AddIntMacro(module, FAN_OPEN_PERM);
    PyModule_AddIntMacro(module, FAN_ACCESS_PERM);
    PyModule_AddIntMacro(module, FAN_ONDIR);
    PyModule_AddIntMacro(module, FAN_EVENT_ON_CHILD);
    PyModule_AddIntMacro(module, FAN_CLOSE);
    PyModule_AddIntMacro(module, FAN_CLOEXEC);
    PyModule_AddIntMacro(module, FAN_NONBLOCK);
    PyModule_AddIntMacro(module, FAN_CLASS_NOTIF);
    PyModule_AddIntMacro(module, FAN_CLASS_CONTENT);
    PyModule_AddIntMacro(module, FAN_CLASS_PRE_CONTENT);
    PyModule_AddIntMacro(module, FAN_UNLIMITED_QUEUE);
    PyModule_AddIntMacro(module, FAN_UNLIMITED_MARKS);
    PyModule_AddIntMacro(module, FAN_MARK_ADD);
    PyModule_AddIntMacro(module, FAN_MARK_REMOVE);
    PyModule_AddIntMacro(module, FAN_MARK_DONT_FOLLOW);
    PyModule_AddIntMacro(module, FAN_MARK_ONLYDIR);
    PyModule_AddIntMacro(module, FAN_MARK_IGNORED_MASK);
    PyModule_AddIntMacro(module, FAN_MARK_IGNORED_SURV_MODIFY);
    PyModule_AddIntMacro(module, FAN_MARK_FLUSH);
    PyModule_AddIntMacro(module, FAN_MARK_MOUNT);
    PyModule_AddIntMacro(module, FANOTIFY_METADATA_VERSION);
    PyModule_AddIntMacro(module, FAN_ALLOW);
    PyModule_AddIntMacro(module, FAN_DENY);
    PyModule_AddIntMacro(module, FAN_AUDIT);
    PyModule_AddIntMacro(module, FAN_NOFD);

    PyModule_AddIntMacro(module, O_CLOEXEC);
    PyModule_AddIntMacro(module, AT_FDCWD);
    PyModule_AddIntMacro(module, CMD_STOP);
    PyModule_AddIntMacro(module, CMD_CONNECT);
    PyModule_AddIntMacro(module, CMD_DISCONNECT);

#ifdef FAN_ENABLE_AUDIT    // (Linux 4.15)
    PyModule_AddIntMacro(module, FAN_ENABLE_AUDIT);
#else
    PyModule_AddIntConstant(module, "FAN_ENABLE_AUDIT", 0);
#endif // FAN_ENABLE_AUDIT (Linux 4.15)

#ifdef FAN_REPORT_TID    // (Linux 4.20)
    PyModule_AddIntMacro(module, FAN_REPORT_TID);
    PyModule_AddIntMacro(module, FAN_MARK_INODE);
    PyModule_AddIntMacro(module, FAN_MARK_FILESYSTEM);
#else
    PyModule_AddIntConstant(module, "FAN_REPORT_TID", 0);
    PyModule_AddIntConstant(module, "FAN_MARK_INODE", 0);
    PyModule_AddIntConstant(module, "FAN_MARK_FILESYSTEM", 0);
#endif // FAN_REPORT_TID (Linux 4.20)

#ifdef FAN_OPEN_EXEC    // (Linux 5.0)
    PyModule_AddIntMacro(module, FAN_OPEN_EXEC);
    PyModule_AddIntMacro(module, FAN_OPEN_EXEC_PERM);
#else
    PyModule_AddIntConstant(module, "FAN_OPEN_EXEC", 0);
    PyModule_AddIntConstant(module, "FAN_OPEN_EXEC_PERM", 0);
#endif // FAN_OPEN_EXEC (Linux 5.0)

#ifdef FAN_REPORT_FID   // (Linux 5.1)
    PyModule_AddIntMacro(module, FAN_ATTRIB);
    PyModule_AddIntMacro(module, FAN_MOVED_FROM);
    PyModule_AddIntMacro(module, FAN_MOVED_TO);
    PyModule_AddIntMacro(module, FAN_MOVE);
    PyModule_AddIntMacro(module, FAN_CREATE);
    PyModule_AddIntMacro(module, FAN_DELETE);
    PyModule_AddIntMacro(module, FAN_DELETE_SELF);
    PyModule_AddIntMacro(module, FAN_MOVE_SELF);
    PyModule_AddIntMacro(module, FAN_REPORT_FID);
#else
    PyModule_AddIntConstant(module, "FAN_ATTRIB", 0);
    PyModule_AddIntConstant(module, "FAN_MOVED_FROM", 0);
    PyModule_AddIntConstant(module, "FAN_MOVED_TO", 0);
    PyModule_AddIntConstant(module, "FAN_MOVE", 0);
    PyModule_AddIntConstant(module, "FAN_CREATE", 0);
    PyModule_AddIntConstant(module, "FAN_DELETE", 0);
    PyModule_AddIntConstant(module, "FAN_DELETE_SELF", 0);
    PyModule_AddIntConstant(module, "FAN_MOVE_SELF", 0);
    PyModule_AddIntConstant(module, "FAN_REPORT_FID", 0);
#endif // FAN_REPORT_FID (Linux 5.1)

#ifdef FAN_REPORT_DIR_FID   // (Linux 5.9)
    PyModule_AddIntMacro(module, FAN_REPORT_DIR_FID);
    PyModule_AddIntMacro(module, FAN_REPORT_NAME);
    PyModule_AddIntMacro(module, FAN_REPORT_DFID_NAME);
#else
    PyModule_AddIntConstant(module, "FAN_REPORT_DIR_FID", 0);
    PyModule_AddIntConstant(module, "FAN_REPORT_NAME", 0);
    PyModule_AddIntConstant(module, "FAN_REPORT_DFID_NAME", 0);
#endif // FAN_REPORT_DIR_FID (Linux 5.9)

#ifdef FAN_RENAME   // (Linux 5.17)
    PyModule_AddIntMacro(module, FAN_RENAME);
#else
    PyModule_AddIntConstant(module, "FAN_RENAME", 0);
#endif

    return module;
}
