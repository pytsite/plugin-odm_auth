"""PytSite ODM Auth Plugin
"""
__author__ = 'Alexander Shepetko'
__email__ = 'a@shepetko.com'
__license__ = 'MIT'

# Public API
from . import _model as model
from ._api import check_permission


def plugin_load():
    from pytsite import events
    from . import _eh

    # Event listeners
    events.listen('odm@entity.pre_save', _eh.odm_entity_pre_save)
    events.listen('odm@entity.pre_delete', _eh.odm_entity_pre_delete)
