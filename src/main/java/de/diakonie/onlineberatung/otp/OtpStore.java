package de.diakonie.onlineberatung.otp;

public interface OtpStore {

  void put(String key, Otp otp);

  Otp get(String key);

  void remove(String key);
}
