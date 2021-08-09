# keycloak-services-social-wechat-work

Keycloak企业微信登录插件

注意只在Keycloak 6.0.1版本下使用过，其他版本情况未知。
Keycloak 15.0.0 测试通过

To build:
`mvn clean package`

To install the social wechat work one has to:

* Add the jar to the Keycloak server (create `providers` folder if needed):
  * `$ cp target/keycloak-services-social-wechat-work-{x.y.z}.jar _KEYCLOAK_HOME_/providers/` 

* Add config page templates to the Keycloak server:
  * `$ cp themes/base/admin/resources/partials/realm-identity-provider-wechat-work.html _KEYCLOAK_HOME_/themes/base/admin/resources/partials/`
  * `$ cp themes/base/admin/resources/partials/realm-identity-provider-wechat-work-ext.html _KEYCLOAK_HOME_/themes/base/admin/resources/partials/`

Be ware you need to fill in corpid, agentid and agent secret.

based on https://github.com/jyqq163/keycloak-services-social-weixin
