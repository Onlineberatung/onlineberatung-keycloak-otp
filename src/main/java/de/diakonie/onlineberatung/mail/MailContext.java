package de.diakonie.onlineberatung.mail;

import java.util.Objects;
import org.keycloak.models.KeycloakSession;

public class MailContext {

  private final String subject;
  private final String textBody;
  private final String htmlBody;
  private final String emailAddress;
  private final KeycloakSession session;

  public MailContext(String subject, String textBody, String htmlBody,
      KeycloakSession session, String emailAddress) {
    this.subject = subject;
    this.textBody = textBody;
    this.htmlBody = htmlBody;
    this.session = session;
    this.emailAddress = emailAddress;
  }

  public String getSubject() {
    return subject;
  }

  public String getTextBody() {
    return textBody;
  }

  public String getHtmlBody() {
    return htmlBody;
  }

  public KeycloakSession getSession() {
    return session;
  }

  public String getEmailAddress() {
    return emailAddress;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    MailContext that = (MailContext) o;
    return Objects.equals(subject, that.subject) && Objects.equals(textBody,
        that.textBody) && Objects.equals(htmlBody, that.htmlBody)
        && Objects.equals(emailAddress, that.emailAddress) && Objects.equals(
        session, that.session);
  }

  @Override
  public int hashCode() {
    return Objects.hash(subject, textBody, htmlBody, emailAddress, session);
  }

  @Override
  public String toString() {
    return "MailContext{" +
        "subject='" + subject + '\'' +
        ", textBody='" + textBody + '\'' +
        ", htmlBody='" + htmlBody + '\'' +
        ", emailAddress='" + emailAddress + '\'' +
        ", session=" + session +
        '}';
  }
}
