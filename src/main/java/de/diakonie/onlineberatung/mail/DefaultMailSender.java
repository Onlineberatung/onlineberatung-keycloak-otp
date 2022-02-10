package de.diakonie.onlineberatung.mail;

import de.diakonie.onlineberatung.otp.Otp;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.keycloak.email.DefaultEmailSenderProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.theme.Theme;

public class DefaultMailSender implements MailSender, OtpMailSender {

  private static final int MINUTE_IN_SECONDS = 60;

  @Override
  public void sendOtpCode(Otp otp, KeycloakSession session, UserModel user, String emailAddress)
      throws Exception {
    var locale = session.getContext().resolveLocale(user);
    var theme = session.theme().getTheme(Theme.Type.LOGIN);
    var bodyTemplate = theme.getMessages(locale).getProperty("emailBody");
    var ttlInMinutes = Math.floorDiv(otp.getTtlInSeconds(), MINUTE_IN_SECONDS);
    var emailBody = String.format(bodyTemplate, otp.getCode(), ttlInMinutes);
    var emailSubject = theme.getMessages(locale).getProperty("emailSubject");
    var mailContext = new MailContext(emailSubject, emailBody, emailBody, session, emailAddress);
    send(mailContext);
  }

  @Override
  public void send(MailContext mailContext) throws Exception {
    var session = mailContext.getSession();
    var smtpConfig = session.getContext().getRealm().getSmtpConfig();
    var user = new MailUser();
    user.emailAddress = mailContext.getEmailAddress();
    var subject = mailContext.getSubject();
    var textBody = mailContext.getTextBody();
    var htmlBody = mailContext.getHtmlBody();
    var emailSenderProvider = new DefaultEmailSenderProvider(session);
    emailSenderProvider.send(smtpConfig, user, subject, textBody, htmlBody);
  }

  // DefaultEmailSenderProvider just needs the email of the user, yet asks for the whole model
  private static class MailUser implements UserModel {

    private String emailAddress;

    @Override
    public String getId() {
      return null;
    }

    @Override
    public String getUsername() {
      return null;
    }

    @Override
    public void setUsername(String username) {

    }

    @Override
    public Long getCreatedTimestamp() {
      return null;
    }

    @Override
    public void setCreatedTimestamp(Long timestamp) {

    }

    @Override
    public boolean isEnabled() {
      return false;
    }

    @Override
    public void setEnabled(boolean enabled) {

    }

    @Override
    public void setSingleAttribute(String name, String value) {

    }

    @Override
    public void setAttribute(String name, List<String> values) {

    }

    @Override
    public void removeAttribute(String name) {

    }

    @Override
    public String getFirstAttribute(String name) {
      return null;
    }

    @Override
    public List<String> getAttribute(String name) {
      return null;
    }

    @Override
    public Map<String, List<String>> getAttributes() {
      return null;
    }

    @Override
    public Set<String> getRequiredActions() {
      return null;
    }

    @Override
    public void addRequiredAction(String action) {

    }

    @Override
    public void removeRequiredAction(String action) {

    }

    @Override
    public String getFirstName() {
      return null;
    }

    @Override
    public void setFirstName(String firstName) {

    }

    @Override
    public String getLastName() {
      return null;
    }

    @Override
    public void setLastName(String lastName) {

    }

    @Override
    public String getEmail() {
      return emailAddress;
    }

    @Override
    public void setEmail(String email) {

    }

    @Override
    public boolean isEmailVerified() {
      return false;
    }

    @Override
    public void setEmailVerified(boolean verified) {

    }

    @Override
    public Set<GroupModel> getGroups() {
      return null;
    }

    @Override
    public void joinGroup(GroupModel group) {

    }

    @Override
    public void leaveGroup(GroupModel group) {

    }

    @Override
    public boolean isMemberOf(GroupModel group) {
      return false;
    }

    @Override
    public String getFederationLink() {
      return null;
    }

    @Override
    public void setFederationLink(String link) {

    }

    @Override
    public String getServiceAccountClientLink() {
      return null;
    }

    @Override
    public void setServiceAccountClientLink(String clientInternalId) {

    }

    @Override
    public Set<RoleModel> getRealmRoleMappings() {
      return null;
    }

    @Override
    public Set<RoleModel> getClientRoleMappings(ClientModel app) {
      return null;
    }

    @Override
    public boolean hasRole(RoleModel role) {
      return false;
    }

    @Override
    public void grantRole(RoleModel role) {

    }

    @Override
    public Set<RoleModel> getRoleMappings() {
      return null;
    }

    @Override
    public void deleteRoleMapping(RoleModel role) {

    }
  }
}

