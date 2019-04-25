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

public class CognitoOIDCAuthenticatorConstants {

    private CognitoOIDCAuthenticatorConstants() {
    }

    public static final String AUTHENTICATOR_NAME = "CognitoOIDCAuthenticator";
    public static final String COGNITO = "Cognito";

    public static final Object COGNITO_LOGOUT = "logout";
    public static final String COGNITO_STATE = "state";

    public static final String CLIENT_ID = "ClientId";
    public static final String CLIENT_SECRET = "ClientSecret";
    public static final String CALLBACK_URL = "callbackUrl";
    public static final String COGNITO_USER_POOL_DOMAIN = "UserPoolDomain";
    public static final String ADDITIONAL_QUERY_PARAMS = "AdditionalQueryParameters";
    public static final String CLAIM_DIALECT_URI_PARAMETER = "ClaimDialectUri";
    public static final String LOGOUT_REDIRECT_URL = "LogoutRedirectUrl";

    public static final String COGNITO_AUTHZ_ENDPOINT = "CognitoAuthzEndpoint";
    public static final String COGNITO_TOKEN_ENDPOINT = "CognitoTokenEndpoint";
    public static final String COGNITO_USER_INFO_ENDPOINT = "CognitoUserInfoEndpoint";
    public static final String COGNITO_LOGOUT_ENDPOINT = "CognitoLogoutEndpoint";

    public static final String COGNITO_LOGOUT_CLIENT_ID = "client_id";
    public static final String COGNITO_LOGOUT_URI = "logout_uri";
    public static final String COGNITO_LOGOUT_STATE_COOKIE = "cognito-logout-state";

    public static final String COGNITO_OAUTH_URL = "/oauth2/authorize";
    public static final String COGNITO_TOKEN_URL = "/oauth2/token";
    public static final String COGNITO_USER_INFO__URL = "/oauth2/userInfo";
    public static final String COGNITO_LOGOUT__URL = "/logout";
}