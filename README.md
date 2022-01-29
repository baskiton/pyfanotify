# pyfanotify
[![PyPI](https://img.shields.io/pypi/v/pyfanotify)](https://pypi.org/project/pyfanotify/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/pyfanotify)](https://pypi.org/project/pyfanotify/)
[![PyPI - License](https://img.shields.io/pypi/l/pyfanotify)](https://github.com/baskiton/pyfanotify/blob/main/LICENSE)

[![build](https://github.com/baskiton/pyfanotify/actions/workflows/build.yml/badge.svg)](https://github.com/baskiton/pyfanotify/actions/workflows/build.yml)
[![upload](https://github.com/baskiton/pyfanotify/actions/workflows/pypi-upload.yml/badge.svg)](https://github.com/baskiton/pyfanotify/actions/workflows/pypi-upload.yml)

Python wrapper for Linux pyfanotify.\
See [fanotify manpage][man_fanotify] for more details.

### IMPORTANT!
`fanotify` requires execution from **ROOT**!

## Requirements
 * Python 3.6+

## Installing
`pip install pyfanotify`

## Building
To build for your platform:
```
python -m build
pip install dist/<target_tar or wheel>
```

## Usage
See [examples][examples] directory

[man_fanotify]: https://man7.org/linux/man-pages/man7/fanotify.7.html
[examples]: https://github.com/baskiton/pyfanotify/blob/main/examples
