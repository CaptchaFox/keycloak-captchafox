package com.captchafox.keycloak.authenticator;

import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.ServicesLogger;
import org.keycloak.util.JsonSerialization;

/**
 * Shared API Verification Client
 */
public final class CaptchaFoxVerifier {
    private static final Logger LOGGER = Logger.getLogger(CaptchaFoxVerifier.class);
    private static final String SITEVERIFY_URL = "https://api.captchafox.com/siteverify";

    public static final String CAPTCHA_RESPONSE_KEY = "cf-captcha-response";
    public static final String SITE_KEY = "site.key";
    public static final String SITE_SECRET = "secret";
    public static final String MODE = "mode";
    public static final String BYPASS_ON_ERROR = "bypass-on-error";
    public static final String SCRIPT_URL = "https://cdn.captchafox.com/api.js";

    /**
     * Outcome of a verification. {@code ERROR} means the verification itself could
     * not be performed (network problem, unexpected response), as opposed to
     * {@code INVALID}, where CaptchaFox rejected the response token.
     */
    public enum Result {
        VALID,
        INVALID,
        ERROR
    }

    private CaptchaFoxVerifier() {
    }

    public static Result verify(KeycloakSession session, String remoteAddr, String captcha, String secret) {
        LOGGER.trace("Verifying CaptchaFox");
        CloseableHttpClient httpClient = session.getProvider(HttpClientProvider.class).getHttpClient();
        HttpPost post = new HttpPost(SITEVERIFY_URL);
        List<NameValuePair> formparams = new LinkedList<>();
        formparams.add(new BasicNameValuePair("secret", secret));
        formparams.add(new BasicNameValuePair("response", captcha));
        formparams.add(new BasicNameValuePair("remoteip", remoteAddr));
        try {
            UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, "UTF-8");
            post.setEntity(form);
            try (CloseableHttpResponse response = httpClient.execute(post)) {
                InputStream content = response.getEntity().getContent();
                try {
                    @SuppressWarnings("rawtypes")
                    Map json = JsonSerialization.readValue(content, Map.class);
                    Object val = json.get("success");
                    return Boolean.TRUE.equals(val) ? Result.VALID : Result.INVALID;
                } finally {
                    EntityUtils.consumeQuietly(response.getEntity());
                }
            }
        } catch (Exception e) {
            ServicesLogger.LOGGER.recaptchaFailed(e);
        }
        return Result.ERROR;
    }
}
