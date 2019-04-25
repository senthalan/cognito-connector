/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.wso2.carbon.identity.application.authenticator.cognito;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.Property;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CognitoOIDCAuthenticator extends OpenIDConnectAuthenticator {

    private static final long serialVersionUID = 9058607724358986002L;
    private static Log log = LogFactory.getLog(CognitoOIDCAuthenticator.class);
    private String tokenEndpoint;
    private String oAuthEndpoint;
    private String logoutEndpoint;
    private String userInfoEnoint;

    @Override
    public boolean canHandle(HttpServletRequest request) {

        if (log.isTraceEnabled()) {
            log.trace("Inside CognitoOIDCAuthenticator.canHandle()");
        }
        boolean canHandle = super.canHandle(request);
        if (CognitoOIDCAuthenticatorConstants.COGNITO_LOGOUT.equals(request.getParameter
                (CognitoOIDCAuthenticatorConstants.COGNITO_STATE)) && getContextIdentifier(request) != null) {
            return true;
        }
        return canHandle;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        if (log.isDebugEnabled()) {
            log.debug("Inside CognitoOIDCAuthenticator.getContextIdentifier()");
        }
        Cookie cookie = FrameworkUtils.getCookie(request, CognitoOIDCAuthenticatorConstants
                .COGNITO_LOGOUT_STATE_COOKIE);
        if (cookie != null) {
            String state = cookie.getValue();
            return state;
        }
        return null;
    }

    @Override
    public String getClaimDialectURI() {

        String claimDialectUri = super.getClaimDialectURI();
        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance().getAuthenticatorBean(getName());
        if (authConfig != null) {
            Map<String, String> parameters = authConfig.getParameterMap();
            if (parameters != null && parameters.containsKey(CognitoOIDCAuthenticatorConstants.
                    CLAIM_DIALECT_URI_PARAMETER)) {
                claimDialectUri = parameters.get(CognitoOIDCAuthenticatorConstants.CLAIM_DIALECT_URI_PARAMETER);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Found no Parameter map for connector " + getName());
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("FileBasedConfigBuilder returned null AuthenticatorConfigs for the connector " +
                        getName());
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Authenticator " + getName() + " is using the claim dialect uri " + claimDialectUri);
        }
        return claimDialectUri;
    }

    private void initTokenEndpoint() {

        this.tokenEndpoint = getAuthenticatorConfig().getParameterMap().get(CognitoOIDCAuthenticatorConstants
                .COGNITO_TOKEN_ENDPOINT);
        if (StringUtils.isBlank(this.tokenEndpoint)) {
            this.tokenEndpoint = CognitoOIDCAuthenticatorConstants.COGNITO_TOKEN_URL;
        }
    }

    private void initOAuthEndpoint() {

        this.oAuthEndpoint = getAuthenticatorConfig().getParameterMap().get(CognitoOIDCAuthenticatorConstants
                .COGNITO_AUTHZ_ENDPOINT);
        if (StringUtils.isBlank(this.oAuthEndpoint)) {
            this.oAuthEndpoint = CognitoOIDCAuthenticatorConstants.COGNITO_OAUTH_URL;
        }
    }

    private void initLogoutURL() {

        logoutEndpoint = getAuthenticatorConfig()
                .getParameterMap()
                .get(CognitoOIDCAuthenticatorConstants.COGNITO_LOGOUT_ENDPOINT);

        if (logoutEndpoint == null) {
            logoutEndpoint = CognitoOIDCAuthenticatorConstants.COGNITO_LOGOUT__URL;
        }
    }

    private void initUserInfoURL() {

        userInfoEnoint = getAuthenticatorConfig().getParameterMap()
                .get(CognitoOIDCAuthenticatorConstants.COGNITO_USER_INFO_ENDPOINT);

        if (userInfoEnoint == null) {
            userInfoEnoint = CognitoOIDCAuthenticatorConstants.COGNITO_USER_INFO__URL;
        }
    }

    @Override
    protected String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {

        String domainName = authenticatorProperties.get(CognitoOIDCAuthenticatorConstants.COGNITO_USER_POOL_DOMAIN);
        if (StringUtils.isBlank(this.oAuthEndpoint)) {
            initOAuthEndpoint();
        }
        return  domainName + this.oAuthEndpoint;
    }

    @Override
    protected String getTokenEndpoint(Map<String, String> authenticatorProperties) {

        String domainName = authenticatorProperties.get(CognitoOIDCAuthenticatorConstants.COGNITO_USER_POOL_DOMAIN);
        if (StringUtils.isBlank(this.tokenEndpoint)) {
            initTokenEndpoint();
        }
        return  domainName + this.tokenEndpoint;
    }

    @Override
    protected String getUserInfoEndpoint(OAuthClientResponse token, Map<String, String> authenticatorProperties) {

        String domainName = authenticatorProperties.get(CognitoOIDCAuthenticatorConstants.COGNITO_USER_POOL_DOMAIN);
        if (StringUtils.isBlank(this.userInfoEnoint)) {
            initUserInfoURL();
        }
        return  domainName + this.userInfoEnoint;
    }


    private String getLogoutUrl(Map<String, String> authenticatorProperties) {

        String domainName = authenticatorProperties.get(CognitoOIDCAuthenticatorConstants.COGNITO_USER_POOL_DOMAIN);
        if (StringUtils.isBlank(this.logoutEndpoint)) {
            initLogoutURL();
        }
        return  domainName + this.logoutEndpoint;
    }

    @Override
    protected String getQueryString(Map<String, String> authenticatorProperties) {

        return authenticatorProperties.get(CognitoOIDCAuthenticatorConstants.ADDITIONAL_QUERY_PARAMS);
    }

    @Override
    public String getFriendlyName() {

        return CognitoOIDCAuthenticatorConstants.COGNITO;
    }

    @Override
    public String getName() {

        return CognitoOIDCAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public List<Property> getConfigurationProperties() {

        List configProperties = new ArrayList();

        Property clientId = new Property();
        clientId.setName(CognitoOIDCAuthenticatorConstants.CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter Cognito client identifier value");
        clientId.setDisplayOrder(1);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(CognitoOIDCAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("Enter Cognito client secret value");
        clientId.setDisplayOrder(2);
        configProperties.add(clientSecret);

        Property callbackUrl = new Property();
        callbackUrl.setDisplayName("Callback Url");
        callbackUrl.setName(CognitoOIDCAuthenticatorConstants.CALLBACK_URL);
        callbackUrl.setDescription("Enter value corresponding to callback url.");
        callbackUrl.setRequired(true);
        callbackUrl.setDisplayOrder(3);
        configProperties.add(callbackUrl);

        Property authzEpUrl = new Property();
        authzEpUrl.setName(CognitoOIDCAuthenticatorConstants.COGNITO_USER_POOL_DOMAIN);
        authzEpUrl.setDisplayName("User Pool Domain");
        authzEpUrl.setRequired(true);
        authzEpUrl.setDescription("Enter Cognito user pool domain");
        authzEpUrl.setDisplayOrder(4);
        configProperties.add(authzEpUrl);

        Property logoutRedirectUrl = new Property();
        logoutRedirectUrl.setName(CognitoOIDCAuthenticatorConstants.LOGOUT_REDIRECT_URL);
        logoutRedirectUrl.setDisplayName("Logout Redirect URL");
        logoutRedirectUrl.setRequired(true);
        logoutRedirectUrl.setDescription("Enter logout redirect url");
        logoutRedirectUrl.setDisplayOrder(5);
        configProperties.add(logoutRedirectUrl);

        Property scope = new Property();
        scope.setDisplayName("Additional Query Parameters");
        scope.setName(CognitoOIDCAuthenticatorConstants.ADDITIONAL_QUERY_PARAMS);
        scope.setDescription("Additional query parameters. e.g: paramName1=value1");
        scope.setDisplayOrder(6);
        configProperties.add(scope);

        return configProperties;
    }

//    @Override
//    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
//                                                 AuthenticationContext context) throws AuthenticationFailedException {
//
//        FrameworkUtils.removeCookie(request, response, CognitoOIDCAuthenticatorConstants.COGNITO_LOGOUT_STATE_COOKIE);
//        super.initiateAuthenticationRequest(request, response, context);
//    }

    @Override
    protected void initiateLogoutRequest(HttpServletRequest request, HttpServletResponse response,
                                         AuthenticationContext context) throws LogoutFailedException {

        if (log.isDebugEnabled()) {
            log.debug("Sending logout request to external IDP");
        }
        String clientId = context.getAuthenticatorProperties().get(CognitoOIDCAuthenticatorConstants.CLIENT_ID);
        String logoutUrl = getLogoutUrl(context.getAuthenticatorProperties());
        String logoutRedirectUrl = context.getAuthenticatorProperties().get(CognitoOIDCAuthenticatorConstants
                .LOGOUT_REDIRECT_URL);

        Map<String, String> parameters = new HashMap<>();

        parameters.put(CognitoOIDCAuthenticatorConstants.COGNITO_LOGOUT_CLIENT_ID, clientId);
        parameters.put(CognitoOIDCAuthenticatorConstants.COGNITO_LOGOUT_URI, logoutRedirectUrl);
        FrameworkUtils.setCookie(request, response, CognitoOIDCAuthenticatorConstants.COGNITO_LOGOUT_STATE_COOKIE,
                context.getContextIdentifier(), null);
        try {
            response.sendRedirect(logoutUrl + "?" + getParamsString(parameters));
        } catch (IOException e) {
            throw new LogoutFailedException("Error while triggering cognito logout", e);
        }

    }

    @Override
    protected void processLogoutResponse(HttpServletRequest request, HttpServletResponse response,
                                         AuthenticationContext context) throws LogoutFailedException {

        FrameworkUtils.removeCookie(request, response, CognitoOIDCAuthenticatorConstants.COGNITO_LOGOUT_STATE_COOKIE);
    }

    private String getParamsString(Map<String, String> params) throws LogoutFailedException {

        StringBuilder result = new StringBuilder();

        try {
            for (Map.Entry<String, String> entry : params.entrySet()) {
                result.append(URLEncoder.encode(entry.getKey(), "UTF-8"));
                result.append("=");
                result.append(URLEncoder.encode(entry.getValue(), "UTF-8"));
                result.append("&");
            }

            String resultString = result.toString();
            return resultString.length() > 0
                    ? resultString.substring(0, resultString.length() - 1)
                    : resultString;
        } catch (UnsupportedEncodingException e) {
            throw new LogoutFailedException(e.getMessage());
        }
    }

}

