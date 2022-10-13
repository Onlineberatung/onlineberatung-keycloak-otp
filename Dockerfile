FROM quay.io/keycloak/keycloak:19.0.3
COPY keycloak-otp-config-spi-1.0-SNAPSHOT-keycloak.jar /opt/keycloak/providers/keycloak-otp-config-spi-1.0-SNAPSHOT-keycloak.jar

ENTRYPOINT /opt/keycloak/bin/kc.sh start --auto-build
