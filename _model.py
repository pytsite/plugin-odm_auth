"""PytSite ODM Authorizable Entity Model
"""
__author__ = 'Oleksandr Shepetko'
__email__ = 'a@shepetko.com'
__license__ = 'MIT'

from typing import Tuple as _Tuple, Iterable as _Iterable, Union as _Union
from pytsite import lang as _lang, logger as _logger, errors as _errors
from plugins import auth as _auth, odm as _odm, permissions as _permissions, odm_http_api as _odm_http_api

PERM_CREATE = 'create'
PERM_MODIFY = 'modify'
PERM_DELETE = 'delete'
PERM_MODIFY_OWN = 'modify_own'
PERM_DELETE_OWN = 'delete_own'


class OwnedEntity(_odm.model.Entity, _odm_http_api.HTTPAPIEntityMixin):
    """Entity which has owner and can be authorized to perform certain actions on it.
    """

    @classmethod
    def on_register(cls, model: str):
        super().on_register(model)

        mock = _odm.dispense(model)  # type: OwnedEntity

        def _on_user_pre_delete(user: _auth.AbstractUser):
            for f in ('owner', 'author'):
                if mock.has_field(f):
                    e = _odm.find(model).eq(f, user).first()
                    if e:
                        raise _errors.ForbidDeletion(_lang.t('odm_auth@forbid_user_deletion', {
                            'user': user.login,
                            'entity': e,
                        }))

        # Check for registered lang package
        lang_pkg_name = cls.lang_package_name()
        if not _lang.is_package_registered(lang_pkg_name):
            raise RuntimeError("In order to use '{}' ODM model the '{}' lang package must be registered".
                               format(model, lang_pkg_name))

        # Register permissions group
        perm_group = cls.odm_auth_permissions_group()

        # Register permissions
        if perm_group:
            for perm_name in mock.odm_auth_permissions():
                # Per-user permission can be registered only if entity has 'author' or 'owner' field
                if perm_name.endswith('_own') and not (mock.has_field('author') or mock.has_field('owner')):
                    continue

                p_name = 'odm_auth@' + perm_name + '.' + model
                p_description = cls.resolve_lang_msg_id('odm_auth_' + perm_name + '_' + model)
                _permissions.define_permission(p_name, p_description, perm_group)

        # Event handlers
        _auth.on_user_pre_delete(_on_user_pre_delete)

    @classmethod
    def odm_auth_permissions_group(cls) -> str:
        """Get model permission group name
        """
        return cls.package_name().split('.')[-1]

    @classmethod
    def odm_auth_permissions(cls) -> _Tuple[str, ...]:
        """Get permissions supported by model
        """
        return PERM_CREATE, PERM_MODIFY, PERM_DELETE, PERM_MODIFY_OWN, PERM_DELETE_OWN

    @classmethod
    def odm_auth_check_model_permissions(cls, model: str, perm: _Union[str, _Iterable[str]],
                                         user: _auth.AbstractUser = None) -> bool:
        """Check if the user can perform operation against ANY entity of model
        """
        # Current user is default
        user = user or _auth.get_current_user()

        # Admins have any permission
        if user.is_admin:
            return True

        # Search for at least one permission in list of permissions
        if isinstance(perm, (list, tuple)):
            for p in perm:
                if cls.odm_auth_check_model_permissions(model, p, user):
                    return True

        # Check for exact permission
        else:
            perm_name = 'odm_auth@{}.{}'.format(perm, model)
            if _permissions.is_permission_defined(perm_name) and user.has_permission(perm_name):
                return True

        # No permission found
        return False

    def odm_auth_check_entity_permissions(self, perm: _Union[str, _Iterable[str]],
                                          user: _auth.AbstractUser = None) -> bool:
        """Check if the user can perform operation against entity
        """
        # Current user is default
        user = user or _auth.get_current_user()

        # Check for model-wide permission
        if self.odm_auth_check_model_permissions(self.model, perm, user):
            return True

        # Search for at least one permission in list of permissions
        if isinstance(perm, (list, tuple)):
            for p in perm:
                if self.odm_auth_check_entity_permissions(p, user):
                    return True

        # Check for exact permission
        else:
            perm_name = 'odm_auth@{}_own.{}'.format(perm, self.model)
            if _permissions.is_permission_defined(perm_name) and user.has_permission(perm_name):
                for author_field in ('author', 'owner'):
                    if self.has_field(author_field) and self.f_get(author_field) == user:
                        return True

        # No permission found
        return False

    def f_get(self, field_name: str, **kwargs):
        """Get field's value
        """
        if not self.is_new and field_name in ('author', 'owner'):
            try:
                return super().f_get(field_name, **kwargs)

            # Owner was deleted or for some reason cannot be accessed
            except _auth.error.UserNotFound:
                try:
                    # Set first admin as owner
                    _auth.switch_user_to_system()
                    self.f_set(field_name, _auth.get_admin_user()).save()
                finally:
                    _auth.restore_user()

                return super().f_get(field_name, **kwargs)

        return super().f_get(field_name, **kwargs)

    def as_jsonable(self, **kwargs):
        r = super().as_jsonable(**kwargs)

        r['permissions'] = {
            PERM_MODIFY: self.odm_auth_check_entity_permissions(PERM_MODIFY),
            PERM_DELETE: self.odm_auth_check_entity_permissions(PERM_DELETE),
        }

        return r

    def _on_pre_save(self, **kwargs):
        super()._on_pre_save(**kwargs)

        c_user = _auth.get_current_user()

        # Admins have unrestricted permissions
        if c_user.is_admin:
            return

        # Check current user's permissions to CREATE entities
        if self.is_new and not self.odm_auth_check_entity_permissions(PERM_CREATE):
            _logger.info('Current user login: {}'.format(_auth.get_current_user().login))
            raise _errors.ForbidCreation("Insufficient permissions to create entities of model '{}'.".
                                         format(self.model))

        # Check current user's permissions to MODIFY entities
        if not self.is_new and not self.odm_auth_check_entity_permissions(PERM_MODIFY):
            _logger.info('Current user login: {}'.format(_auth.get_current_user().login))
            raise _errors.ForbidModification("Insufficient permissions to modify entity '{}:{}'.".
                                             format(self.model, self.id))

    def _on_pre_delete(self, **kwargs):
        super()._on_pre_delete(**kwargs)

        c_user = _auth.get_current_user()

        # Admins have unrestricted permissions
        if c_user.is_admin:
            return

        # Check current user's permissions to DELETE entities
        if not self.odm_auth_check_entity_permissions(PERM_DELETE):
            _logger.debug('Current user login: {}'.format(_auth.get_current_user().login))
            raise _errors.ForbidDeletion("Insufficient permissions to delete entity '{}:{}'".
                                         format(self.model, self.id))
