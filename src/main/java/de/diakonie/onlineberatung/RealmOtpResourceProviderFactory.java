package de.diakonie.onlineberatung;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class RealmOtpResourceProviderFactory implements RealmResourceProviderFactory {

  public static final String ID = "otp-config";

  @Override
  public RealmResourceProvider create(KeycloakSession keycloakSession) {
    return new RealmOtpResourceProvider(keycloakSession);
  }

  @Override
  public void init(Scope scope) {

  }

  @Override
  public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

  }

  @Override
  public void close() {

  }

  @Override
  public String getId() {
    return ID;
  }
}
