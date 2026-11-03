#!/bin/sh
set -eu
python -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else "Python >=3.10 required")'
