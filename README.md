# keycloak-services-social-weixin

To install the SMS Authenticator one has to:

* Add the jar to the Keycloak server:
  * `$ cp target/keycloak-services-social-weixin-*.jar _KEYCLOAK_HOME_/providers/`

* Add three templates to the Keycloak server:
  * `$ cp templates/realm-identity-provider-weixin.html _KEYCLOAK_HOME_/themes/base/admin/resources/partials`
  * `$ cp templates/realm-identity-provider-weixin-ext.html _KEYCLOAK_HOME_/themes/base/admin/resources/partials`
