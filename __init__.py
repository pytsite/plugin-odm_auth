"""PytSite ODM Auth Plugin
"""
__author__ = 'Oleksandr Shepetko'
__email__ = 'a@shepetko.com'
__license__ = 'MIT'

# Public API
from . import _model as model
from ._api import check_model_permissions
from ._model import OwnedEntity, PERM_CREATE, PERM_MODIFY, PERM_DELETE, PERM_MODIFY_OWN, PERM_DELETE_OWN
