FROM jboss/keycloak:16.1.1
COPY ./keycloak-otp-config-spi-1.0-SNAPSHOT-keycloak.jar /opt/jboss/keycloak/standalone/deployments/keycloak-otp-config-spi-1.0-SNAPSHOT-keycloak.jar
