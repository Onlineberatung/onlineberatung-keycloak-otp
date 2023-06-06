FROM quay.io/keycloak/keycloak:20.0.5
COPY target/keycloak-otp-config-spi-1.0-SNAPSHOT-keycloak.jar /opt/keycloak/providers/keycloak-otp-config-spi-1.0-SNAPSHOT-keycloak.jar

ENTRYPOINT /opt/keycloak/bin/kc.sh start --auto-build
