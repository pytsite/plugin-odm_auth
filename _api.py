"""PytSite ODM Auth API Functions
"""
__author__ = 'Oleksandr Shepetko'
__email__ = 'a@shepetko.com'
__license__ = 'MIT'

from typing import Union as _Union, Iterable as _Iterable
from plugins import auth as _auth, odm as _odm
from . import _model


def check_model_permissions(model: str, perm: _Union[str, _Iterable[str]],
                            user: _auth.model.AbstractUser = None) -> bool:
    """Convenient shortcut function to check if the user can perform operation against ANY entity of model
    """
    cls = _odm.get_model_class(model)
    if not issubclass(cls, _model.OwnedEntity):
        raise TypeError('{} expected, got {}'.format(_model.OwnedEntity, type(cls)))

    return cls.odm_auth_check_model_permissions(model, perm, user)
