package de.diakonie.onlineberatung.otp;


import java.security.SecureRandom;
import org.keycloak.common.util.RandomString;

public class RandomDigitsCodeGenerator implements OtpGenerator {

  @Override
  public String generate(int length) {
    return new RandomString(length, new SecureRandom(), RandomString.digits).nextString();
  }

}
