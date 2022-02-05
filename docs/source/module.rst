pyfanotify
==========

.. py:module:: pyfanotify
    :platform: Linux

.. currentmodule:: pyfanotify

.. note::
    Requires execution from **ROOT**!

.. autoclass:: Fanotify
    :exclude-members: run
    :member-order: bysource

.. autoclass:: FanoRule
    :exclude-members: __new__, __init__, name, pids, ev_types,
        exe_pattern, cwd_pattern, path_pattern, pass_fd

.. autoclass:: FanotifyClient

.. autoclass:: FanotifyData

    .. attribute:: fd
        :type: int
        :value: -1

        File descriptor if passed, -1 otherwise

    .. attribute:: pid
        :type: int
        :value: 0

        PID of caused process

    .. attribute:: ev_types
        :type: int
        :value: 0

        Event types of fanotify event

    .. attribute:: exe
        :type: str
        :value: None

        EXE of the event caused process if passed, :py:const:`None` otherwise

    .. attribute:: cwd
        :type: str
        :value: None

        CWD of the event caused process if passed, :py:const:`None` otherwise

    .. attribute:: path
        :type: str
        :value: None

        PATH of the event caused file if passed, :py:const:`None` otherwise
