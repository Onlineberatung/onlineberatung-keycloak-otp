package de.diakonie.onlineberatung.otp;

import de.diakonie.onlineberatung.otp.Otp;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;

public interface OtpMailSender {

  void sendOtpCode(Otp otp, KeycloakSession session, UserModel user, String emailAddress) throws Exception;

}