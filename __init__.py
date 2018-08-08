"""PytSite ODM Auth Plugin
"""
__author__ = 'Oleksandr Shepetko'
__email__ = 'a@shepetko.com'
__license__ = 'MIT'

# Public API
from . import _model as model
from ._api import check_permission


def plugin_load():
    from pytsite import lang

    lang.register_package(__name__)
