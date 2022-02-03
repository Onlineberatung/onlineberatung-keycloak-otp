FROM jboss/keycloak:16.1.1
COPY ./target/keycloak-otp-config-spi-1.0-SNAPSHOT-keycloak.jar /opt/jboss/keycloak/standalone/deployments/keycloak-otp-config-spi-1.0-SNAPSHOT-keycloak.jar
COPY ./standalone-ha.xml /opt/jboss/keycloak/standalone/configuration/standalone-ha.xml