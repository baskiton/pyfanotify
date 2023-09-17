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
#include <sys/vfs.h>
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
#define PID_CACHE_SIZE 64

enum RUN_ERR_CODE {
    PY_FILLED_ERR = -100,
    FANO_MISMATCH_VER,
};

typedef struct c_rule c_rule_t;
typedef struct _fs_list fs_list_t;

typedef struct {
    pid_t pid;
    char our;
} pid_cache_t;

typedef struct {
    c_rule_t *rules;
    fs_list_t *fs_list;
    pid_cache_t *cache_idx;
    pid_cache_t pid_cache[PID_CACHE_SIZE];
    long main_pid;
    int fano_fd;
    int log_fd;
    int sock_fd;
} fano_ctx_t;

typedef struct str_val {
    uint32_t len;
    char buf[PATH_MAX];
} str_val_t;

typedef struct {
    char *buf;
    size_t bufsz;
    size_t size;
} buffer_t;

#define BUFFER_INIT { .bufsz = 512 }

// ### FMonRule ###############################################################
struct c_rule {
    c_rule_t *next;
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
rules_list_add(c_rule_t **rules, ext_FanoRule *rule)
{
    ssize_t hash = PyObject_Hash(rule->name.obj);
    while (*rules) {
        if (hash == (*rules)->hash)
            return;
        rules = &(*rules)->next;
    }
    c_rule_t *new;
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
rules_list_raw_del(c_rule_t **rules, long hash)
{
    while (*rules) {
        if (hash == (*rules)->hash) {
            c_rule_t *next = (*rules)->next;
            PyMem_Free((*rules)->pids);
            PyMem_Free(*rules);
            *rules = next;
            return;
        }
        rules = &(*rules)->next;
    }
}

static void
rules_list_del(c_rule_t **rules, ext_FanoRule *rule)
{
    rules_list_raw_del(rules, PyObject_Hash(rule->name.obj));
}

static void
rules_list_clear(c_rule_t **rules)
{
    c_rule_t *item = *rules;
    while (item) {
        c_rule_t *next = item->next;
        PyMem_Free(item->pids);
        PyMem_Free(item);
        item = next;
    }
    *rules = 0;
}

static unsigned char
rule_pids_check(c_rule_t *rule, pid_t pid)
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
// ### ! FMonRule #############################################################

// ### FMonRule ###############################################################
struct _fs_list {
    fs_list_t *next;
    char *path;
    fsid_t fsid;
    int fd;
};

static void
fs_list_add(fs_list_t **list, const char *path)
{
    while (*list) {
        if (!strcmp((*list)->path, path))
            // already exist
            return;
        list = &(*list)->next;
    }

    struct statfs buf;
    if (statfs(path, &buf))
        return;

    fs_list_t *new = PyMem_Malloc(sizeof(*new));
    if (!new || !(new->path = PyMem_Malloc(strlen(path) + 1))) {
        PyMem_Free(new);
        return;
    }

    new->next = NULL;
    new->fd = open(path, O_RDONLY | O_DIRECTORY);
    strcpy(new->path, path);
    memcpy(&new->fsid, &buf.f_fsid, sizeof(new->fsid));

    *list = new;
}

static void
fs_list_del(fs_list_t **list, const char *path)
{
    while (*list) {
        if (!strcmp((*list)->path, path)) {
            fs_list_t *next = (*list)->next;
            close((*list)->fd);
            PyMem_Free((*list)->path);
            PyMem_Free((*list));
            *list = next;
            return;
        }
        list = &(*list)->next;
    }
}

static void
fs_list_clear(fs_list_t **list)
{
    fs_list_t *item = *list;
    while (item) {
        fs_list_t *next = item->next;
        close(item->fd);
        PyMem_Free(item->path);
        PyMem_Free(item);
        item = next;
    }
    *list = 0;
}

static fs_list_t *
fs_list_get_fs(fs_list_t **list, fsid_t *fsid)
{
    while (*list) {
        if (!memcmp(&(*list)->fsid, fsid, sizeof(*fsid)))
            return *list;
        list = &(*list)->next;
    }
    return NULL;
}
// ### ! FMonRule #############################################################

PyDoc_STRVAR(create__doc__,
"create() -> int\n"
"\n"
"Create fanotify context\n"
"\n"
"Raises:\n"
"    OSError\n");

static PyObject *
pyfanotify_create(PyObject *self, PyObject *args, PyObject *kwargs)
{
    fano_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return PyErr_SetFromErrno(PyExc_OSError);

    ctx->fano_fd = ctx->log_fd = ctx->sock_fd = -1;
    ctx->cache_idx = ctx->pid_cache;
    ctx->main_pid = getpid();

    return PyLong_FromVoidPtr(ctx);
}

PyDoc_STRVAR(init__doc__,
"init(ctx: int, flags: int, o_flags: int) -> int\n"
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
    static char *kwlist[] = {"ctx", "flags", "o_flags", NULL};
    long long ctx_ptr;
    unsigned int flags, o_flags = 0;
    fano_ctx_t *ctx;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "LII:init", kwlist,
                                     &ctx_ptr, &flags, &o_flags))
        return NULL;

    if (!(ctx = (void *)ctx_ptr)) {
        PyErr_SetString(PyExc_ValueError, "Invalid context");
        return NULL;
    }

    ctx->fano_fd = fanotify_init(flags, o_flags);
    if (ctx->fano_fd == -1)
        return PyErr_SetFromErrno(PyExc_OSError);

    return PyLong_FromLong(ctx->fano_fd);
}

PyDoc_STRVAR(mark__doc__,
"mark(ctx: int, flags: int, mask: int, dirfd: int, pathname: str = None) -> None\n"
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
    static char *kwlist[] = {"ctx", "flags", "mask", "dirfd", "pathname", NULL};
    long long ctx_ptr;
    unsigned int flags = 0;
    uint64_t mask = 0;
    int dirfd = -1;
    const char *pathname = NULL;
    fano_ctx_t *ctx;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "LIKi|z:mark", kwlist,
                                     &ctx_ptr, &flags, &mask, &dirfd, &pathname))
        return NULL;

    if (!(ctx = (void *)ctx_ptr)) {
        PyErr_SetString(PyExc_ValueError, "Invalid context");
        return NULL;
    }

    int err = fanotify_mark(ctx->fano_fd, flags, mask, dirfd, pathname);
    if (err == -1) {
        if (pathname)
            return PyErr_SetFromErrnoWithFilename(PyExc_OSError, pathname);
        else
            return PyErr_SetFromErrno(PyExc_OSError);
    }
    if (!(flags & (FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORED_SURV_MODIFY))
            && flags & (FAN_MARK_FILESYSTEM | FAN_MARK_ONLYDIR)) {
        if (flags & FAN_MARK_ADD)
            fs_list_add(&ctx->fs_list, pathname);
        else
            fs_list_del(&ctx->fs_list, pathname);
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
do_log(fano_ctx_t *ctx, const char *fmt, ...)
{
    if (ctx->fano_fd < 0)
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
    do_write(ctx->fano_fd, &msg, len + hdr_len);
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

static char *
_readfd(buffer_t *bb, int fd)
{
    bb->size = 0;
    ssize_t n;
    size_t tot = 0;
    do {
        if ((tot >= bb->bufsz || !bb->buf) && !(bb->buf = realloc(bb->buf, bb->bufsz <<= 1)))
            return 0;
        if ((n = read(fd, &bb->buf[tot], bb->bufsz - tot)) != -1)
            tot += n;
        else if (errno != EINTR)
            return 0;
    } while (n);
    bb->size = tot;
    return bb->buf;
}

static pid_cache_t *
pid_cache_check(fano_ctx_t *ctx, buffer_t *bb, pid_t pid)
{
    pid_cache_t *c = ctx->cache_idx;
    for (unsigned i = PID_CACHE_SIZE; i--;) {
        if (c->pid == pid)
            return c;
        if (++c >= &ctx->pid_cache[PID_CACHE_SIZE])
            c = ctx->pid_cache;
    }

    if (c-- == ctx->pid_cache)
        c = &ctx->pid_cache[PID_CACHE_SIZE - 1];
    *c = (pid_cache_t){.pid = pid};

    long p = (long)pid;
    for (;;) {
        if (p == ctx->main_pid) {
            c->our = 1;
            break;
        }

        char path[64], *ptr;
        snprintf(path, sizeof(path), "/proc/%ld/stat", p);
        int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY);
        if (fd == -1)
            break;

        char *buf = _readfd(bb, fd);
        close(fd);
        if (!buf)
            break;
        buf[bb->size] = 0;

        if (!(ptr = strrchr(buf, ')')))
            break;
        ptr += 4;

        // fields: https://man7.org/linux/man-pages/man5/proc.5.html
        // field #4 - PPid
        if (!(p = (long)strtoull(ptr, 0, 10)))
            break;
    }

    return (ctx->cache_idx = c);
}

static int
handle_events(fano_ctx_t *ctx)
{
    struct fanotify_event_metadata buf[256];
    ssize_t len;
    buffer_t bb = BUFFER_INIT;
    int ret = 0;

    if ((len = read(ctx->fano_fd, buf, sizeof(buf))) == -1) {
        ret = errno;
        goto end;
    }

    for (struct fanotify_event_metadata *ev = buf;
            FAN_EVENT_OK(ev, len);
            close(ev->fd), ev = FAN_EVENT_NEXT(ev, len)){
        if (ev->vers != FANOTIFY_METADATA_VERSION) {
            ret = FANO_MISMATCH_VER;
            goto end;
        }

        if (pid_cache_check(ctx, &bb, ev->pid)->our)
            // skip ours
            continue;

        str_val_t exe, cwd, path, evt;
        exe.buf[0] = cwd.buf[0] = path.buf[0] = evt.buf[0] = '\0';
        exe.len = cwd.len = path.len = evt.len = 0;
        c_rule_t to_del;

#ifdef FAN_REPORT_FID
        if (ev->event_len != FAN_EVENT_METADATA_LEN) {
            struct fanotify_event_info_fid *fid;
            struct fanotify_event_info_header *finfo = (struct fanotify_event_info_header *)(ev + 1);
//            struct fanotify_event_info_pidfd *pidfd;
//            struct fanotify_event_info_error *ierror;
            struct file_handle *file_handle = NULL;
            const char *file_name = NULL;
            ssize_t info_len = ev->event_len - ev->metadata_len;
            ssize_t rest = info_len;
            int ffd = FAN_NOFD, dfd = FAN_NOFD, *_fd = NULL;

            int cont = 0;
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
                    goto fid_end;
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
                    int evt_fd;
                    fs_list_t *fs = fs_list_get_fs(&ctx->fs_list, (void *)&fid->fsid);
                    if (!fs || (((evt_fd = open_by_handle_at(fs->fd, file_handle, O_FLAGS)) == FAN_NOFD)
                                && (errno == ESTALE)))
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
                cont = 1;
        fid_end:
            if (cont)
                continue;
        }
#endif // FAN_REPORT_FID

        for (c_rule_t *rule = ctx->rules; rule; rule = rule->next) {

# define RULE_MATCH(name, fmt, meta)    \
        (rule->name##_pattern.len       \
            && (!((name).buf[0]         \
                    || ((name).len = get_proc_str(fmt, ev->meta, (name).buf, sizeof((name).buf))))  \
                || fnmatch(rule->name##_pattern.buf, (name).buf, FNM_EXTMATCH)))

            if (rule_pids_check(rule, ev->pid)
                    || (rule->ev_types && !(rule->ev_types & ev->mask))
                    || RULE_MATCH(exe, "/proc/%ld/exe", pid)
                    || RULE_MATCH(cwd, "/proc/%ld/cwd", pid)
                    || RULE_MATCH(path, "/proc/self/fd/%ld", fd))
                continue;
# undef RULE_MATCH

            // sending data
            struct {
                int64_t pid;
                uint64_t ev_types;
            } data = {ev->pid, ev->mask};
            struct iovec iov[] = {
                    {&data, sizeof(data)},
                    {&exe, exe.len + sizeof(exe.len)},
                    {&cwd, cwd.len + sizeof(exe.len)},
                    {&path, path.len + sizeof(exe.len)},
            };
            struct sockaddr_un addr = {.sun_family = AF_UNIX};
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
            if (rule->pass_fd && ev->fd != FAN_NOFD) {
                cmsg.cm.cmsg_len = sizeof(cmsg),
                cmsg.cm.cmsg_level = SOL_SOCKET,
                cmsg.cm.cmsg_type = SCM_RIGHTS,
                cmsg.fd = ev->fd,
                msg.msg_control = &cmsg;
                msg.msg_controllen = sizeof(cmsg);
            }

            for (int i = 0; i < 3; ++i) {
                if (sendmsg(ctx->sock_fd, &msg, 0) < 0) {
                    if ((AGAIN && (usleep(250000) <= 0)) || errno == EINTR)
                        continue;

                    int e = errno;
                    do_log(ctx, "FileMonitor: send_data error for %s: %s",
                          rule->name.buf, strerror(e));
                    if (e == ECONNREFUSED) {
                        do_log(ctx, "FileMonitor: delete \"%s\"", rule->name.buf);
                        to_del.next = rule->next;
                        rules_list_raw_del(&ctx->rules, rule->hash);
                        rule = &to_del;
                    }
                }
                break;
            }
        }
    }
end:
    free(bb.buf);
    return ret;
}

PyDoc_STRVAR(run__doc__,
"run(ctx: int, rcon: Connection[, log_fd: int, fn, fn_args, fn_timeout=0]) -> None\n"
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
"    ctx (int): Fanotify context.\n"
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
    static char *kwlist[] = {"ctx", "rcon",
                             "log_fd", "fn", "fn_args", "fn_timeout", 0};
    long long ctx_ptr;
    int rfd = -1, err = 0, log_fd = -1;
    time_t fn_timeout = 0;
    pid_t ppid = getppid();
    fano_ctx_t *ctx;
    PyObject *rcon, *tmp = NULL, *fn = NULL, *fn_args = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "LO|iOOl:run", kwlist,
                                     &ctx_ptr, &rcon,
                                     &log_fd, &fn, &fn_args, &fn_timeout))
        return 0;

    if (!(ctx = (void *)ctx_ptr)) {
        PyErr_SetString(PyExc_ValueError, "Invalid context");
        err = PY_FILLED_ERR;
        fn = fn_args = 0;
        goto end;
    }
    ctx->log_fd = log_fd;

    if (ctx->fano_fd < 0) {
        err = errno = EBADF;
        fn = fn_args = 0;
        goto end;
    }
    if (fn_timeout < 0) {
        PyErr_SetString(PyExc_ValueError, "timeout must be non-negative");
        err = PY_FILLED_ERR;
        fn = fn_args = 0;
        goto end;
    }
    if (PyObject_IsTrue(fn) > 0) {
        if (PyCallable_Check(fn)) {
            Py_INCREF(fn);
        } else {
            fn = fn_args = NULL;
            err = PY_FILLED_ERR;
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
        err = PY_FILLED_ERR;
        goto end;
    }
    Py_XDECREF(tmp);
    tmp = NULL;

    struct pollfd fds[] = {
        {rfd, POLLIN, 0},
        {ctx->fano_fd, POLLIN, 0},
    };

    if ((ctx->sock_fd = socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0)) == -1) {
        err = errno;
        goto end;
    }

    time_t fn_timer = 0;
    PyThreadState *state = PyEval_SaveThread();
    while (ppid == getppid()) {
        do {
            if (ctx->rules && fn) {
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
            c_rule_t *old = ctx->rules;
            PyEval_RestoreThread(state);

            int cmd;
            PyObject *val = NULL;
            if (!((tmp = PyObject_CallMethod(rcon, "recv", NULL))
                    && PyArg_ParseTuple(tmp, "i|O", &cmd, &val))) {
                Py_XDECREF(tmp);
                err = PY_FILLED_ERR;
                goto end;
            }
            switch (cmd) {
            case CMD_STOP:
                Py_XDECREF(tmp);
                err = 0;
                goto end;
            case CMD_CONNECT:
                rules_list_add(&ctx->rules, (void *)val);
                break;
            case CMD_DISCONNECT:
                rules_list_del(&ctx->rules, (void *)val);
            default:
                break;
            }
            Py_XDECREF(tmp);

            state = PyEval_SaveThread();
            if (!old && ctx->rules)
                fn_timer = 0;
            else if (old && !ctx->rules) {   // flush
                fanotify_mark(ctx->fano_fd, FAN_MARK_FLUSH, 0, AT_FDCWD, 0);
                fanotify_mark(ctx->fano_fd, FAN_MARK_FLUSH | FAN_MARK_MOUNT, 0, AT_FDCWD, 0);
            }

        } else if (fds[0].revents & POLLNVAL) {
            err = errno = EBADF;
            break;
        }

        if (fds[1].revents & POLLIN) {
            if ((err = handle_events(ctx)))
                break;
        } else if (fds[1].revents & POLLNVAL) {
            err = errno = EBADF;
            break;
        }
    }
    PyEval_RestoreThread(state);

end:
    if (dup2(1, ctx->fano_fd) == -1)
        close(ctx->fano_fd);
    close(ctx->sock_fd);
    rules_list_clear(&ctx->rules);
    fs_list_clear(&ctx->fs_list);
    free(ctx);
    Py_XDECREF(fn);
    Py_XDECREF(fn_args);
    switch (err) {
    case 0:
        Py_RETURN_NONE;
    case FANO_MISMATCH_VER:
        PyErr_SetString(PyExc_AssertionError, "Mismatch of fanotify metadata version.");
        return 0;
    default:
        errno = err;
        PyErr_SetFromErrno(PyExc_OSError);
    case PY_FILLED_ERR:
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
        {"create", (PyCFunction)pyfanotify_create, METH_NOARGS, create__doc__},
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
