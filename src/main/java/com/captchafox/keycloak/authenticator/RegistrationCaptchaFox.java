/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.captchafox.keycloak.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.Config.Scope;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;

import jakarta.ws.rs.core.MultivaluedMap;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class RegistrationCaptchaFox implements FormAction, FormActionFactory {
    private static final Logger LOGGER = Logger.getLogger(RegistrationCaptchaFox.class);
    public static final String CAPTCHA_RESPONSE_KEY = "cf-captcha-response";
    public static final String REFERENCE_CATEGORY = "captchafox";
    public static final String SITE_KEY = "site.key";
    public static final String SITE_SECRET = "secret";

    public static final String PROVIDER_ID = "registration-captchafox-action";

    @Override
    public void close() {

    }

    @Override
    public FormAction create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Scope config) {

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
        return "CaptchaFox";
    }

    @Override
    public String getReferenceCategory() {
        return REFERENCE_CATEGORY;
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
    public String getHelpText() {
        return "Adds CaptchaFox button. CaptchaFox verifies that the entity that is registering is a human. This can only be used on the internet and must be configured after you add it.";
    }

    @Override
    public void buildPage(FormContext context, LoginFormsProvider form) {
        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        String userLanguageTag = context.getSession().getContext().resolveLocale(context.getUser()).toLanguageTag();

        if (captchaConfig == null || captchaConfig.getConfig() == null
                || captchaConfig.getConfig().get(SITE_KEY) == null
                || captchaConfig.getConfig().get(SITE_SECRET) == null) {
            form.addError(new FormMessage(null, Messages.RECAPTCHA_NOT_CONFIGURED));
            return;
        }

        String siteKey = captchaConfig.getConfig().get(SITE_KEY);
        String mode = captchaConfig.getConfig().get("mode");
        form.setAttribute("captchaFoxRequired", true);
        form.setAttribute("captchaFoxMode", mode);
        form.setAttribute("captchaFoxSiteKey", siteKey);
        form.addScript("https://cdn.captchafox.com/api.js?lang=" + userLanguageTag);

    }

    @Override
    public void validate(ValidationContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList<>();
        context.getEvent().detail(Details.REGISTER_METHOD, "form");

        String captcha = formData.getFirst(CAPTCHA_RESPONSE_KEY);
        LOGGER.trace("Got captcha response: " + captcha);

        if (!Validation.isBlank(captcha)) {
            AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
            String secret = captchaConfig.getConfig().get(SITE_SECRET);

            Boolean success = validateCaptcha(context, captcha, secret);
            if (success) {
                context.success();
                return;
            }
        }

        errors.add(new FormMessage(null, Messages.RECAPTCHA_FAILED));
        formData.remove(CAPTCHA_RESPONSE_KEY);
        context.error(Errors.INVALID_REGISTRATION);
        context.validationError(formData, errors);
        context.excludeOtherErrors();
    }

    protected boolean validateCaptcha(ValidationContext context, String captcha, String secret) {
        return CaptchaFoxVerifier.verify(context.getSession(), context.getConnection().getRemoteAddr(), captcha,
                secret) == CaptchaFoxVerifier.Result.VALID;
    }

    @Override
    public void success(FormContext context) {

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
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

}
