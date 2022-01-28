import select

import pyfanotify as fan


def foo(t):
    print(f'calling `foo` every {t} seconds')


if __name__ == '__main__':
    foo_timeout = 1
    fanot = fan.Fanotify(fn=foo, fn_args=(foo_timeout,), fn_timeout=foo_timeout)
    fanot.mark('/home', is_type='mp')
    fanot.start()

    cli = fan.FanotifyClient(fanot, path_pattern='/home/*')
    poll = select.poll()
    poll.register(cli.sock.fileno(), select.POLLIN)
    try:
        while poll.poll():
            x = {}
            for i in cli.get_events():
                x[i.path] = i
            if x:
                print(x)
    except:
        print('STOP')

    cli.close()
    fanot.stop()
