# PytSite Authorizable ODM Entities Plugin


## Changelog


### 4.1.3 (2019-06-04)

Bugfix of `OwnedEntity.odm_auth_check_model_permissions()`.


### 4.1.2 (2019-06-04)

Bugfix of `OwnedEntity.odm_auth_check_entity_permissions()`.


### 4.1.1 (2019-06-03)

Permission existence checking fixed in 
`odm_auth_check_entity_permissions()`.


### 4.1 (2019-06-03)

- `model` returned to the public API.
- Permission name checking added to 
  `odm_auth_check_model_permissions()`.
- Permission existence checking removed from 
  `odm_auth_check_model_permissions()` and 
  `odm_auth_check_entity_permissions()`.


### 4.0 (2019-06-02)

- Removed support of `owner` field.
- Removed `model` from the public API.


### 3.2 (2019-05-27)

`PERM_*` constants introduced.


### 3.1.1 (2019-05-23)

Little refactoring of `model.OwnedEntity` permission checking related 
methods.


### 3.1 (2019-03-04)

Support of `odm-6.0`.


### 3.0 (2019-01-07)

- API function `check_permission()` refactored and renamed to
  `check_model_permissions()`.
- `OwnedEntity.check_permission()` splitted into
  `odm_auth_check_model_permissions()` and
  `odm_auth_check_entity_permissions()`.


### 2.4 (2018-12-12)

Support of `odm_http_api-5.x`.


### 2.3 (2018-12-06)

Support of `odm_http_api` added.


### 2.2 (2018-12-04)

`OwnedEntity.as_jsonable()` implemented.


### 2.1 (2018-11-03)

Support of `odm-5.1`.


### 2.0 (2018-10-11)

Suport of `pytsite-8.x`.


### 1.9.1 (2018-09-14)

Unnecessary permissions checking removed.


### 1.9 (2018-08-09)

View related permissions removed.


### 1.8 (2018-06-24)

`check_permission()` logic fixed.


### 1.7 (2018-04-25)

Support of `auth-3.0`.


### 1.6 (2018-04-08)

Support of `auth-2.3`.


### 1.5.1 (2018-04-07)

`plugin.json` fixed.


### 1.5 (2018-04-06)

- Support of `auth-2.0`.
- Permissions creating logic refactored.


### 1.4 (2018-03-18)

Support for list as a first argument in `check_permission()`.


### 1.3 (2018-01-27)

Support for `auth-1.8`.


### 1.2 (2017-12-13)

Support for PytSite-7.0.


### 1.1 (2017-12-02)

Support for last `auth` plugin update.


### 1.0 (2017-11-26)

First release.
