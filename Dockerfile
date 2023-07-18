FROM quay.io/keycloak/keycloak:21.1.2
COPY keycloak-otp-config-spi-1.0-SNAPSHOT-keycloak.jar /opt/keycloak/providers/keycloak-otp-config-spi-1.0-SNAPSHOT-keycloak.jar

ENTRYPOINT /opt/keycloak/bin/kc.sh start --auto-build
