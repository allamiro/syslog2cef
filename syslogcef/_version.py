"""Package version and author, shown by ``syslogcef --version``.

Kept in step with ``version`` in pyproject.toml (checked by the test
suite). A module constant rather than importlib.metadata, because the
standalone .pyz has no installed distribution metadata to read.
"""

__version__ = "0.6.1"
__author__ = "Tamir Suliman"
__email__ = "allamiro@gmail.com"
__copyright__ = "Copyright (c) 2023 Tamir Suliman"
__license__ = "MIT"
