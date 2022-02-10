package de.diakonie.onlineberatung.mail;

public interface MailSender {

  void send(MailContext mailContext) throws Exception;

}
