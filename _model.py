"""PytSite ODM Authorizable Entity Model
"""
__author__ = 'Alexander Shepetko'
__email__ = 'a@shepetko.com'
__license__ = 'MIT'

from typing import Tuple as _Tuple, Iterable as _Iterable, Union as _Union
from pytsite import lang as _lang
from plugins import auth as _auth, odm as _odm, permissions as _permissions


class OwnedEntity(_odm.model.Entity):
    """Entity which has owner and can be authorized to perform certain actions on it.
    """

    @classmethod
    def on_register(cls, model: str):
        super().on_register(model)

        # Determining model's package name
        pkg_name = cls.get_package_name()

        # Registering package's language resources
        if not _lang.is_package_registered(pkg_name):
            raise RuntimeError("Language package '{}' is not registered".format(pkg_name))

        # Register permissions
        perm_group = cls.odm_auth_permissions_group()
        if perm_group:
            # Register permissions
            mock = _odm.dispense(model)  # type: OwnedEntity
            for perm_name in mock.odm_auth_permissions():
                if perm_name.endswith('_own') and not mock.has_field('author') and not mock.has_field('owner'):
                    continue

                p_name = 'odm_auth@' + perm_name + '.' + model
                p_description = cls.resolve_msg_id('odm_auth_' + perm_name + '_' + model)
                _permissions.define_permission(p_name, p_description, perm_group)

    @classmethod
    def odm_auth_permissions_group(cls) -> str:
        """Get model permission group name
        """
        return cls.get_package_name().split('.')[-1]

    @classmethod
    def odm_auth_permissions(cls) -> _Tuple[str, ...]:
        """Get permissions supported by model
        """
        return 'create', 'view', 'modify', 'delete', 'view_own', 'modify_own', 'delete_own'

    def odm_auth_check_permission(self, perm: _Union[str, _Iterable[str]],
                                  user: _auth.model.AbstractUser = None) -> bool:
        """Check user's permissions
        """
        from . import _api
        return _api.check_permission(perm, self.model, self.id, user)

    def f_get(self, field_name: str, **kwargs):
        """Get field's value
        """
        if not self.is_new and field_name in ('author', 'owner'):
            try:
                return super().f_get(field_name, **kwargs)

            # Owner was deleted or for some reason cannot be accessed
            except _auth.error.UserNotFound:
                # Set first admin as owner
                _auth.switch_user_to_system()
                self.f_set(field_name, _auth.get_admin_user()).save()
                _auth.restore_user()

                return super().f_get(field_name, **kwargs)

        return super().f_get(field_name, **kwargs)
