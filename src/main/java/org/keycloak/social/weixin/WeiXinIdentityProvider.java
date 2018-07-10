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
package org.keycloak.social.weixin;

import java.io.IOException;
import java.util.UUID;

import javax.ws.rs.GET;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * LinkedIn social provider. See https://developer.linkedin.com/docs/oauth2
 * 
 * @author Vlastimil Elias (velias at redhat dot com)
 */
public class WeiXinIdentityProvider extends AbstractOAuth2IdentityProvider<OAuth2IdentityProviderConfig>
		implements SocialIdentityProvider<OAuth2IdentityProviderConfig> {

	public static final String AUTH_URL = "https://open.weixin.qq.com/connect/qrconnect";
	public static final String TOKEN_URL = "https://api.weixin.qq.com/sns/oauth2/access_token";
	public static final String DEFAULT_SCOPE = "snsapi_login";

	public static final String OAUTH2_PARAMETER_CLIENT_ID = "appid";
	public static final String OAUTH2_PARAMETER_CLIENT_SECRET = "secret";
	
	public static final String OPENID = "openid";

	public WeiXinIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
		super(session, config);
		config.setAuthorizationUrl(AUTH_URL);
		config.setTokenUrl(TOKEN_URL);
	}
	
	@Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new Endpoint(callback, realm, event);
    }
	
	@Override
	protected boolean supportsExternalExchange() {
		return true;
	}

	@Override
	protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
		BrokeredIdentityContext user = new BrokeredIdentityContext(getJsonProperty(profile, "unionid")+getJsonProperty(profile, "openid"));
		user.setUsername(getJsonProperty(profile, "openid"));
		user.setModelUsername(getJsonProperty(profile, "openid"));
		user.setName(getJsonProperty(profile, "nickname"));
		user.setIdpConfig(getConfig());
		user.setIdp(this);
		user.setBrokerUserId(getJsonProperty(profile, "openid"));
		AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());
		return user;
	}
	
	 public BrokeredIdentityContext getFederatedIdentity(String response) {
       String accessToken = extractTokenFromResponse(response, getAccessTokenResponseParameter());
       if (accessToken == null) {
           throw new IdentityBrokerException("No access token available in OAuth server response: " + response);
       }

       BrokeredIdentityContext context = null;
		try {
			context = extractIdentityFromProfile(null,new ObjectMapper().readTree(response));
		} catch (IOException e) {
			logger.error(e);
		}
       context.getContextData().put(FEDERATED_ACCESS_TOKEN, accessToken);
       return context;
   }

	@Override
	protected String getDefaultScopes() {
		return DEFAULT_SCOPE;
	}

	@Override
	protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
		final UriBuilder uriBuilder = UriBuilder.fromUri(getConfig().getAuthorizationUrl())
				.queryParam(OAUTH2_PARAMETER_SCOPE, getConfig().getDefaultScope())
				.queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded())
				.queryParam(OAUTH2_PARAMETER_RESPONSE_TYPE, "code")
				.queryParam(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getClientId())
				.queryParam(OAUTH2_PARAMETER_REDIRECT_URI, request.getRedirectUri());

		String loginHint = request.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);
		if (getConfig().isLoginHint() && loginHint != null) {
			uriBuilder.queryParam(OIDCLoginProtocol.LOGIN_HINT_PARAM, loginHint);
		}

		String prompt = getConfig().getPrompt();
		if (prompt == null || prompt.isEmpty()) {
			prompt = request.getAuthenticationSession().getClientNote(OAuth2Constants.PROMPT);
		}
		if (prompt != null) {
			uriBuilder.queryParam(OAuth2Constants.PROMPT, prompt);
		}

		String nonce = request.getAuthenticationSession().getClientNote(OIDCLoginProtocol.NONCE_PARAM);
		if (nonce == null || nonce.isEmpty()) {
			nonce = UUID.randomUUID().toString();
			request.getAuthenticationSession().setClientNote(OIDCLoginProtocol.NONCE_PARAM, nonce);
		}
		uriBuilder.queryParam(OIDCLoginProtocol.NONCE_PARAM, nonce);

		String acr = request.getAuthenticationSession().getClientNote(OAuth2Constants.ACR_VALUES);
		if (acr != null) {
			uriBuilder.queryParam(OAuth2Constants.ACR_VALUES, acr);
		}
		return uriBuilder;
	}

	protected class Endpoint {
		protected AuthenticationCallback callback;
		protected RealmModel realm;
		protected EventBuilder event;

		@Context
		protected KeycloakSession session;

		@Context
		protected ClientConnection clientConnection;

		@Context
		protected HttpHeaders headers;

		@Context
		protected UriInfo uriInfo;

		public Endpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event) {
			this.callback = callback;
			this.realm = realm;
			this.event = event;
		}

		@GET
		public Response authResponse(@QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
				@QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode,
				@QueryParam(OAuth2Constants.ERROR) String error) {
			logger.info("OAUTH2_PARAMETER_CODE=" + authorizationCode);
			if (error != null) {
				// logger.error("Failed " + getConfig().getAlias() + " broker
				// login: " + error);
				if (error.equals(ACCESS_DENIED)) {
					logger.error(ACCESS_DENIED + " for broker login " + getConfig().getProviderId());
					return callback.cancelled(state);
				} else {
					logger.error(error + " for broker login " + getConfig().getProviderId());
					return callback.error(state, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
				}
			}

			try {

				if (authorizationCode != null) {
					String response = generateTokenRequest(authorizationCode).asString();
					//logger.info("response=" + response);
					BrokeredIdentityContext federatedIdentity = getFederatedIdentity(response);

					if (getConfig().isStoreToken()) {
						// make sure that token wasn't already set by
						// getFederatedIdentity();
						// want to be able to allow provider to set the token
						// itself.
						if (federatedIdentity.getToken() == null)
							federatedIdentity.setToken(response);
					}

					federatedIdentity.setIdpConfig(getConfig());
					federatedIdentity.setIdp(WeiXinIdentityProvider.this);
					federatedIdentity.setCode(state);

					return callback.authenticated(federatedIdentity);
				}
			} catch (WebApplicationException e) {
				return e.getResponse();
			} catch (Exception e) {
				logger.error("Failed to make identity provider oauth callback", e);
			}
			event.event(EventType.LOGIN);
			event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
			return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY,
					Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
		}

		public SimpleHttp generateTokenRequest(String authorizationCode) {
			return SimpleHttp.doPost(getConfig().getTokenUrl(), session).param(OAUTH2_PARAMETER_CODE, authorizationCode)
					.param(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getClientId())
					.param(OAUTH2_PARAMETER_CLIENT_SECRET, getConfig().getClientSecret())
					.param(OAUTH2_PARAMETER_REDIRECT_URI, uriInfo.getAbsolutePath().toString())
					.param(OAUTH2_PARAMETER_GRANT_TYPE, OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE);
		}
	}
}
