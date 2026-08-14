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
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

/**
 * Renders a page containing only the captcha for any authentication flow that is not a form flow.
 */
public class CaptchaFoxAuthenticator implements Authenticator, AuthenticatorFactory {
    private static final Logger LOGGER = Logger.getLogger(CaptchaFoxAuthenticator.class);
    private static final String TEMPLATE = "captchafox.ftl";

    public static final String PROVIDER_ID = "captchafox-authenticator";
    public static final String REFERENCE_CATEGORY = "captchafox";

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
    public String getDisplayType() {
        return "CaptchaFox Challenge";
    }

    @Override
    public String getReferenceCategory() {
        return REFERENCE_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Shows a standalone CaptchaFox challenge. CaptchaFox verifies that the entity performing the request is a human. Can be added to any flow and must be configured after you add it.";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {
                AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        context.challenge(buildForm(context));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (config == null || config.getConfig() == null
                || config.getConfig().get(CaptchaFoxVerifier.SITE_SECRET) == null) {
            LOGGER.error("CaptchaFox is not configured for execution " + context.getExecution().getId());
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, buildForm(context));
            return;
        }

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String captcha = formData.getFirst(CaptchaFoxVerifier.CAPTCHA_RESPONSE_KEY);
        LOGGER.trace("Got captcha response: " + captcha);

        String secret = config.getConfig().get(CaptchaFoxVerifier.SITE_SECRET);
        boolean bypassOnError = Boolean.parseBoolean(config.getConfig().get(CaptchaFoxVerifier.BYPASS_ON_ERROR));

        CaptchaFoxVerifier.Result result = Validation.isBlank(captcha)
                ? CaptchaFoxVerifier.Result.INVALID
                : CaptchaFoxVerifier.verify(context.getSession(), context.getConnection().getRemoteAddr(), captcha,
                        secret);

        if (result == CaptchaFoxVerifier.Result.VALID) {
            context.success();
            return;
        }

        if (result == CaptchaFoxVerifier.Result.ERROR && bypassOnError) {
            LOGGER.warn(
                    "CaptchaFox verification could not be performed, continuing because bypass on error is enabled");
            context.success();
            return;
        }

        LoginFormsProvider form = context.form().addError(new FormMessage(null, Messages.RECAPTCHA_FAILED));
        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, buildForm(context, form));
    }

    protected Response buildForm(AuthenticationFlowContext context) {
        return buildForm(context, context.form());
    }

    protected Response buildForm(AuthenticationFlowContext context, LoginFormsProvider form) {
        AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
        Map<String, String> captchaConfig = authenticatorConfig != null ? authenticatorConfig.getConfig() : null;

        if (captchaConfig == null
                || captchaConfig.get(CaptchaFoxVerifier.SITE_KEY) == null
                || captchaConfig.get(CaptchaFoxVerifier.SITE_SECRET) == null) {
            form.addError(new FormMessage(null, Messages.RECAPTCHA_NOT_CONFIGURED));
            return form.createForm(TEMPLATE);
        }

        String userLanguageTag = context.getSession().getContext().resolveLocale(context.getUser()).toLanguageTag();
        form.setAttribute("captchaFoxRequired", true);
        form.setAttribute("captchaFoxMode", captchaConfig.get(CaptchaFoxVerifier.MODE));
        form.setAttribute("captchaFoxSiteKey", captchaConfig.get(CaptchaFoxVerifier.SITE_KEY));
        form.addScript(CaptchaFoxVerifier.SCRIPT_URL + "?lang=" + userLanguageTag);

        return form.createForm(TEMPLATE);
    }

    @Override
    public boolean requiresUser() {
        return false;
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
        property.setName(CaptchaFoxVerifier.SITE_KEY);
        property.setLabel("CaptchaFox Site Key");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("CaptchaFox Site Key");
        CONFIG_PROPERTIES.add(property);
        property = new ProviderConfigProperty();
        property.setName(CaptchaFoxVerifier.SITE_SECRET);
        property.setLabel("CaptchaFox Secret");
        property.setType(ProviderConfigProperty.PASSWORD);
        property.setHelpText("CaptchaFox Organization Secret");
        CONFIG_PROPERTIES.add(property);
        property = new ProviderConfigProperty();
        property.setName(CaptchaFoxVerifier.MODE);
        property.setLabel("CaptchaFox Mode");
        property.setType(ProviderConfigProperty.LIST_TYPE);
        property.setOptions(Arrays.asList("inline", "popup"));
        property.setDefaultValue("inline");
        property.setHelpText("Display Mode");
        CONFIG_PROPERTIES.add(property);
        property = new ProviderConfigProperty();
        property.setName(CaptchaFoxVerifier.BYPASS_ON_ERROR);
        property.setLabel("Bypass on Error");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setHelpText("Continues the flow even if the captcha validation runs into an error");
        CONFIG_PROPERTIES.add(property);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }
}
