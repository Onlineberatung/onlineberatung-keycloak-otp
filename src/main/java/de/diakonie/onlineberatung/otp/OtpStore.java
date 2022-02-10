package de.diakonie.onlineberatung.otp;

import static java.util.Objects.isNull;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.annotation.Nonnull;

public class OtpStore implements Map<String, Otp> {

  private static OtpStore instance;

  private final ConcurrentHashMap<String, Otp> otpStore;

  private OtpStore() {
    this.otpStore = new ConcurrentHashMap<>();
  }

  public static synchronized Map<String, Otp> getInstance() {
    if (isNull(instance)) {
      instance = new OtpStore();
    }
    return instance;
  }

  @Override
  public int size() {
    return otpStore.size();
  }

  @Override
  public boolean isEmpty() {
    return otpStore.isEmpty();
  }

  @Override
  public boolean containsKey(Object key) {
    return otpStore.isEmpty();
  }

  @Override
  public boolean containsValue(Object value) {
    return otpStore.containsValue(value);
  }

  @Override
  public Otp get(Object key) {
    return otpStore.get(key);
  }

  @Override
  public Otp put(String key, Otp value) {
    return otpStore.put(key, value);
  }

  @Override
  public Otp remove(Object key) {
    return otpStore.remove(key);
  }

  @Override
  public void putAll(Map<? extends String, ? extends Otp> m) {
    otpStore.putAll(m);
  }

  @Override
  public void clear() {
    otpStore.clear();
  }

  @Override
  @Nonnull
  public Set<String> keySet() {
    return otpStore.keySet();
  }

  @Override
  public Collection<Otp> values() {
    return otpStore.values();
  }

  @Override
  @Nonnull
  public Set<Entry<String, Otp>> entrySet() {
    return otpStore.entrySet();
  }

}
