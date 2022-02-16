# diakonie-onlineberatung-keycloak-otp

Adds additional endpoints to keycloak to configure 2FA. Currently supports 2FA via:

* App (e.g. Google Authenticator)
* Email

## Installation

* Create a jar (e.g. mvn package)
* Copy `keycloak-otp-config-spi-<VERSION>-keycloak.jar` into the keycloak deployments folder.
  E.g. `/opt/jboss/keycloak/standalone/deployments`
* Keycloak will pick up the deployment. If it is deployed successfully, a `.deployed` file will
  appear in the deployments folder with the same name as the jar.
  E.g. `keycloak-otp-config-spi-<VERSION>-keycloak.jar.deployed`
* Configure Authentication flow for direct grant.