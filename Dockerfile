FROM quay.io/keycloak/keycloak:17.0.0
COPY ./target/keycloak-otp-config-spi-1.0-SNAPSHOT-keycloak.jar /opt/keycloak/providers/keycloak-otp-config-spi-1.0-SNAPSHOT-keycloak.jar

ENTRYPOINT /opt/keycloak/bin/kc.sh start --auto-build
