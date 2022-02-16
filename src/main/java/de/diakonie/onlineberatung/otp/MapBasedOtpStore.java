package de.diakonie.onlineberatung.otp;

import static java.util.Objects.isNull;

import java.util.concurrent.ConcurrentHashMap;

public class MapBasedOtpStore implements OtpStore {

  private static MapBasedOtpStore instance;

  private final ConcurrentHashMap<String, Otp> otpStore;

  private MapBasedOtpStore() {
    this.otpStore = new ConcurrentHashMap<>();
  }

  public static synchronized MapBasedOtpStore getInstance() {
    if (isNull(instance)) {
      instance = new MapBasedOtpStore();
    }
    return instance;
  }

  @Override
  public void put(String key, Otp otp) {
    otpStore.put(key, otp);
  }

  @Override
  public Otp get(String key) {
    return otpStore.get(key);
  }

  @Override
  public void remove(String key) {
    otpStore.remove(key);
  }
}
