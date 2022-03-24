package de.diakonie.onlineberatung.mail;

import static java.util.Collections.emptyList;

import de.diakonie.onlineberatung.credential.CredentialContext;
import de.diakonie.onlineberatung.otp.Otp;
import de.diakonie.onlineberatung.otp.OtpMailSender;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.email.freemarker.FreeMarkerEmailTemplateProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.theme.FreeMarkerUtil;

public class DefaultMailSender implements OtpMailSender {

  private static final int MINUTE_IN_SECONDS = 60;
  private static final String OTP_MAIL_TEMPLATE = "otp-email.ftl";
  private static final String EMAIL_SUBJECT = "emailSubject";
  private static final String OTP_ATTRIBUTE = "otp";
  private static final String TTL_ATTRIBUTE = "ttl";

  @Override
  public void sendOtpCode(Otp otp, CredentialContext context) throws MailSendingException {
    try {
      var mailRecipient = createMailRecipient(otp);
      var mailAttributes = createMailAttributes(otp);
      var mailTemplateProvider = createMailTemplateProvider(context, mailRecipient);

      mailTemplateProvider.send(EMAIL_SUBJECT, emptyList(), OTP_MAIL_TEMPLATE, mailAttributes);
    } catch (Exception e) {
      throw new MailSendingException("failed to send otp mail", e);
    }
  }

  private UserModel createMailRecipient(Otp otp) {
    var mailRecipient = new MailUser();
    mailRecipient.setEmail(otp.getEmail());
    return mailRecipient;
  }

  private HashMap<String, Object> createMailAttributes(Otp otp) {
    var attributes = new HashMap<String, Object>();
    attributes.put(OTP_ATTRIBUTE, otp.getCode());
    var ttlInSeconds = otp.getTtlInSeconds() > 0 ? otp.getTtlInSeconds() : 60;
    attributes.put(TTL_ATTRIBUTE, Math.floorDiv(ttlInSeconds, MINUTE_IN_SECONDS));
    return attributes;
  }

  private EmailTemplateProvider createMailTemplateProvider(CredentialContext context,
      UserModel mailRecipient) {
    var freeMarker = new FreeMarkerUtil();
    var emailTemplateProvider = new FreeMarkerEmailTemplateProvider(context.getSession(),
        freeMarker);
    emailTemplateProvider.setRealm(context.getRealm());
    emailTemplateProvider.setUser(mailRecipient);
    return emailTemplateProvider;
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
      emailAddress = email;
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

