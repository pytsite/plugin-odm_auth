"""PytSite ODM Auth Event Handlers
"""
__author__ = 'Alexander Shepetko'
__email__ = 'a@shepetko.com'
__license__ = 'MIT'

from pytsite import logger as _logger, errors as _errors
from plugins import auth as _auth
from . import _model


def odm_entity_pre_save(entity: _model.OwnedEntity):
    """odm.entity_pre_save
    """
    # Check if the model supports permissions
    if not isinstance(entity, _model.OwnedEntity):
        return

    c_user = _auth.get_current_user()

    # System user and admins have unrestricted permissions
    if c_user.is_system or c_user.is_admin_or_dev:
        return

    # Check current user's permissions to CREATE entities
    if entity.is_new and not entity.odm_auth_check_permission('create'):
        _logger.info('Current user login: {}'.format(_auth.get_current_user().login))
        raise _errors.ForbidCreation("Insufficient permissions to create entities of model '{}'.".
                                     format(entity.model))

    # Check current user's permissions to MODIFY entities
    if not entity.is_new and not entity.odm_auth_check_permission('modify'):
        _logger.info('Current user login: {}'.format(_auth.get_current_user().login))
        raise _errors.ForbidModification("Insufficient permissions to modify entity '{}:{}'.".
                                         format(entity.model, entity.id))


def odm_entity_pre_delete(entity: _model.OwnedEntity):
    """'odm.entity_pre_delete' event handler
    """
    # Check if the model supports permissions
    if not isinstance(entity, _model.OwnedEntity):
        return

    c_user = _auth.get_current_user()

    # System user and admins have unrestricted permissions
    if c_user.is_system or c_user.is_admin_or_dev:
        return

    # Check current user's permissions to DELETE entities
    if not entity.odm_auth_check_permission('delete'):
        _logger.debug('Current user login: {}'.format(_auth.get_current_user().login))
        raise _errors.ForbidDeletion("Insufficient permissions to delete entity '{}:{}'".
                                     format(entity.model, entity.id))
