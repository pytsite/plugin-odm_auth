"""PytSite ODM Auth API Functions
"""
__author__ = 'Alexander Shepetko'
__email__ = 'a@shepetko.com'
__license__ = 'MIT'

from typing import Union as _Union, Iterable as _Iterable
from bson.objectid import ObjectId as _ObjectId
from plugins import auth as _auth, permissions as _permissions, odm as _odm


def check_permission(perm_type: _Union[str, _Iterable[str]], model: str, entity_id: _Union[_ObjectId, str, None] = None,
                     user: _auth.model.AbstractUser = None) -> bool:
    """Check current user's permissions to operate with entity(es).
    """
    if isinstance(perm_type, (list, tuple)):
        for pt in perm_type:
            if check_permission(pt, model, entity_id, user):
                return True

        return False

    if not user:
        user = _auth.get_current_user()

    if user.is_admin:
        return True

    # In case of personal permission name was provided
    perm_type = perm_type.replace('_own', '')

    # Check if the user has global permission
    global_perm_name = 'odm_auth@{}.{}'.format(perm_type, model)
    if _permissions.is_permission_defined(global_perm_name) and user.has_permission(global_perm_name):
        return True

    # Check user's personal permission for particular entity
    personal_perm_name = 'odm_auth@{}_own.{}'.format(perm_type, model)
    if entity_id and _permissions.is_permission_defined(personal_perm_name) and user.has_permission(personal_perm_name):
        # Load entity
        entity = _odm.dispense(model, entity_id)

        # Nobody can do anything with non-existent entities
        if not entity:
            return False

        # Check author of the entity
        for author_field in 'author', 'owner':
            if entity.has_field(author_field) and entity.f_get(author_field) == user:
                return True

    return False
