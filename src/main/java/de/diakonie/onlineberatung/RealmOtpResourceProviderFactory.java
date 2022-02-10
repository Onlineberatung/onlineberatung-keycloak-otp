package de.diakonie.onlineberatung;

import de.diakonie.onlineberatung.authenticator.BearerTokenSessionAuthenticator;
import de.diakonie.onlineberatung.mail.DefaultMailSender;
import de.diakonie.onlineberatung.otp.MemoryOtpService;
import de.diakonie.onlineberatung.otp.OtpStore;
import de.diakonie.onlineberatung.otp.RandomDigitsCodeGenerator;
import java.time.Clock;
import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class RealmOtpResourceProviderFactory implements RealmResourceProviderFactory {

  public static final String ID = "otp-config";

  @Override
  public RealmResourceProvider create(KeycloakSession keycloakSession) {
    var systemClock = Clock.systemDefaultZone();
    var otpGenerator = new RandomDigitsCodeGenerator();
    var mailSender = new DefaultMailSender();
    var otpMailService = new MemoryOtpService(OtpStore.getInstance(), otpGenerator, systemClock);
    return new RealmOtpResourceProvider(keycloakSession, otpMailService, mailSender,
        new BearerTokenSessionAuthenticator());
  }

  @Override
  public void init(Scope scope) {
    // Do nothing because it is not needed
  }

  @Override
  public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
    // Do nothing because it is not needed
  }

  @Override
  public void close() {
    // Do nothing because it is not needed
  }

  @Override
  public String getId() {
    return ID;
  }
}