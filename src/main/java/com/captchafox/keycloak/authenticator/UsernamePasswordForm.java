package com.captchafox.keycloak.authenticator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

public class UsernamePasswordForm extends AbstractUsernameFormAuthenticator implements AuthenticatorFactory {
    private static final Logger LOGGER = Logger.getLogger(UsernamePasswordForm.class);
    public static final String CAPTCHA_RESPONSE_KEY = "cf-captcha-response";
    public static final String SITE_KEY = "site.key";
    public static final String SITE_SECRET = "secret";
    public static final String BYPASS_ON_ERROR = "bypass-on-error";
    public static final String PROVIDER_ID = "username-password-captchafox";

    @Override
    public void close() {
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getReferenceCategory() {
        return "captcha";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getDisplayType() {
        return "CaptchaFox Username Password Form";
    }

    @Override
    public String getHelpText() {
        return "Adds CaptchaFox verification to the Username and Password Form";
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        boolean success = false;

        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        String secret = captchaConfig.getConfig().get(SITE_SECRET);
        Boolean bypassOnError = Boolean.parseBoolean(captchaConfig.getConfig().get(BYPASS_ON_ERROR));
        String captcha = formData.getFirst(CAPTCHA_RESPONSE_KEY);
        LOGGER.trace("Got captcha response: " + captcha);

        try {
            success = this.validateCaptcha(context, captcha, secret);
        } catch (Exception e) {
            success = false;
        }

        if (!success && !bypassOnError) {
            context.form().addError(new FormMessage(null, Messages.RECAPTCHA_FAILED));
            Response challengeResponse = buildForm(context);
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
                    challengeResponse);
            return;
        }

        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            return;
        }
        if (!validateForm(context, formData)) {
            return;
        }
        context.success();
    }

    protected boolean validateCaptcha(AuthenticationFlowContext context, String captcha, String secret) {
        return CaptchaFoxVerifier.verify(context.getSession(), context.getConnection().getRemoteAddr(), captcha,
                secret) == CaptchaFoxVerifier.Result.VALID;
    }

    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        buildForm(context);
        return validateUserAndPassword(context, formData);
    }

    public Response buildForm(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        String loginHint = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);
        String rememberMeUsername = AuthenticationManager.getRememberMeUsername(context.getSession());

        if (context.getUser() != null) {
            LoginFormsProvider form = context.form();
            form.setAttribute(LoginFormsProvider.USERNAME_HIDDEN, true);
            form.setAttribute(LoginFormsProvider.REGISTRATION_DISABLED, true);
            context.getAuthenticationSession().setAuthNote(USER_SET_BEFORE_USERNAME_PASSWORD_AUTH, "true");
        } else {
            LoginFormsProvider form = context.form();

            AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
            Map<String, String> captchaConfig = authenticatorConfig.getConfig();
            String userLanguageTag = context.getSession().getContext().resolveLocale(context.getUser()).toLanguageTag();

            if (captchaConfig == null
                    || captchaConfig.get(SITE_KEY) == null
                    || captchaConfig.get(SITE_SECRET) == null) {
                form.addError(new FormMessage(null, Messages.RECAPTCHA_NOT_CONFIGURED));
                return null;
            }

            String siteKey = captchaConfig.get(SITE_KEY);
            String mode = captchaConfig.get("mode");
            form.setAttribute("captchaFoxRequired", true);
            form.setAttribute("captchaFoxMode", mode);
            form.setAttribute("captchaFoxSiteKey", siteKey);
            form.addScript("https://cdn.captchafox.com/api.js?lang=" + userLanguageTag);

            context.getAuthenticationSession().removeAuthNote(USER_SET_BEFORE_USERNAME_PASSWORD_AUTH);
            if (loginHint != null || rememberMeUsername != null) {
                if (loginHint != null) {
                    formData.add(AuthenticationManager.FORM_USERNAME, loginHint);
                } else {
                    formData.add(AuthenticationManager.FORM_USERNAME, rememberMeUsername);
                    formData.add("rememberMe", "on");
                }
            }
        }

        return challenge(context, formData);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Response challengeResponse = buildForm(context);
        context.challenge(challengeResponse);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        LoginFormsProvider forms = context.form();

        if (formData.size() > 0)
            forms.setFormData(formData);

        return forms.createLoginUsernamePassword();
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(SITE_KEY);
        property.setLabel("CaptchaFox Site Key");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("CaptchaFox Site Key");
        CONFIG_PROPERTIES.add(property);
        property = new ProviderConfigProperty();
        property.setName(SITE_SECRET);
        property.setLabel("CaptchaFox Secret");
        property.setType(ProviderConfigProperty.PASSWORD);
        property.setHelpText("CaptchaFox Organization Secret");
        CONFIG_PROPERTIES.add(property);
        property = new ProviderConfigProperty();
        property.setName("mode");
        property.setLabel("CaptchaFox Mode");
        property.setType(ProviderConfigProperty.LIST_TYPE);
        property.setOptions(Arrays.asList("inline", "popup"));
        property.setDefaultValue("inline");
        property.setHelpText("Display Mode");
        CONFIG_PROPERTIES.add(property);
        property = new ProviderConfigProperty();
        property.setName(BYPASS_ON_ERROR);
        property.setLabel("Bypass on Error");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setHelpText("Allows login even if the captcha validation runs into an error");
        CONFIG_PROPERTIES.add(property);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }
}