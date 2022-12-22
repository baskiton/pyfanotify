# pyfanotify
[![PyPI](https://img.shields.io/pypi/v/pyfanotify?logo=python&logoColor=white)][pypi_proj]
[![PyPI - Downloads](https://img.shields.io/pypi/dm/pyfanotify?logo=python&logoColor=white)][pypi_proj]
[![PyPI - License](https://img.shields.io/pypi/l/pyfanotify?logo=open-source-initiative&logoColor=white)](https://github.com/baskiton/pyfanotify/blob/main/LICENSE)

[![build](https://img.shields.io/github/actions/workflow/status/baskiton/pyfanotify/build.yml?logo=github)](https://github.com/baskiton/pyfanotify/actions/workflows/build.yml)
[![upload](https://img.shields.io/github/actions/workflow/status/baskiton/pyfanotify/pypi-upload.yml?label=upload&logo=github)](https://github.com/baskiton/pyfanotify/actions/workflows/pypi-upload.yml)
[![docs](https://img.shields.io/readthedocs/pyfanotify?logo=readthedocs&logoColor=white)][documentation]

Python wrapper for Linux fanotify. \
See [fanotify manpage][man_fanotify] for more details.

To detail see the [documentation][documentation]

### IMPORTANT!
`fanotify` requires execution from **ROOT**!

## Requirements
 * Python 3.6+

## Installing
### Using PIP
```sh
$ pip install pyfanotify
```
### From sources
```sh
$ git clone https://github.com/baskiton/pyfanotify.git
$ cd pyfanotify
$ python setup.py install
```

## Usage
See [examples][examples]


[pypi_proj]: https://pypi.org/project/pyfanotify/
[man_fanotify]: https://man7.org/linux/man-pages/man7/fanotify.7.html
[examples]: https://github.com/baskiton/pyfanotify/blob/main/examples
[documentation]: https://pyfanotify.readthedocs.io
