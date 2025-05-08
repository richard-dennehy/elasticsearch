/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

package org.elasticsearch.plugin.security.authz;

import com.nimbusds.jose.util.JSONObjectUtils;

import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.core.Tuple;
import org.elasticsearch.logging.LogManager;
import org.elasticsearch.logging.Logger;
import org.elasticsearch.xpack.core.security.authc.AuthenticationResult;
import org.elasticsearch.xpack.core.security.authc.AuthenticationToken;
import org.elasticsearch.xpack.core.security.authc.Realm;
import org.elasticsearch.xpack.core.security.authc.RealmConfig;
import org.elasticsearch.xpack.core.security.authc.support.UserRoleMapper;
import org.elasticsearch.xpack.core.security.user.User;

import java.net.URI;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class MicrosoftGraphAuthzRealm extends Realm {

    private static final Logger logger = LogManager.getLogger(MicrosoftGraphAuthzRealm.class);

    private final HttpClient httpClient;
    private final RealmConfig config;
    private final UserRoleMapper roleMapper;

    public MicrosoftGraphAuthzRealm(UserRoleMapper roleMapper, RealmConfig config) {
        super(config);

        this.roleMapper = roleMapper;
        this.config = config;
        this.httpClient = HttpClients.createDefault();
    }

    @Override
    public boolean supports(AuthenticationToken token) {
        return false;
    }

    @Override
    public AuthenticationToken token(ThreadContext context) {
        return null;
    }

    @Override
    public void authenticate(AuthenticationToken token, ActionListener<AuthenticationResult<User>> listener) {
        listener.onResponse(AuthenticationResult.notHandled());
    }

    @Override
    public void lookupUser(String principal, ActionListener<User> listener) {
        try {
            var authenticate = new HttpPost(
                Strings.format(
                    "%s/%s/oauth2/v2.0/token",
                    config.getSetting(MicrosoftGraphAuthzRealmSettings.ACCESS_TOKEN_HOST),
                    config.getSetting(MicrosoftGraphAuthzRealmSettings.TENANT_ID)
                )
            );
            authenticate.setEntity(
                new UrlEncodedFormEntity(
                    List.of(
                        new BasicNameValuePair("grant_type", "client_credentials"),
                        new BasicNameValuePair("scope", "https://graph.microsoft.com/.default"),
                        new BasicNameValuePair("client_id", config.getSetting(MicrosoftGraphAuthzRealmSettings.CLIENT_ID)),
                        new BasicNameValuePair("client_secret", config.getSetting(MicrosoftGraphAuthzRealmSettings.CLIENT_SECRET))
                    )
                )
            );
            logger.trace("getting bearer token from {}", authenticate.getURI());
            var response = httpClient.execute(authenticate, new BasicResponseHandler());

            var json = JSONObjectUtils.parse(response);
            var bearer = json.get("access_token");
            logger.trace("Azure access token [{}]", bearer);

            var getUserInfo = new HttpGet(
                Strings.format(
                    "%s/v1.0/users/%s?$select=mail,displayName",
                    config.getSetting(MicrosoftGraphAuthzRealmSettings.API_HOST),
                    principal
                )
            );
            getUserInfo.addHeader("Authorization", "Bearer " + bearer);
            logger.trace("getting user info from {}", getUserInfo.getURI());
            response = httpClient.execute(getUserInfo, new BasicResponseHandler());
            var userInfo = parseUserInfo(response);
            var name = userInfo.v2();
            var email = userInfo.v1();
            logger.trace("User [{}] has email [{}]", name, email);

            var getGroupMembership = new HttpGet(
                Strings.format(
                    "%s/v1.0/users/%s/memberOf/microsoft.graph.group?$select=id&$top=999",
                    config.getSetting(MicrosoftGraphAuthzRealmSettings.API_HOST),
                    principal
                )
            );
            getGroupMembership.addHeader("Authorization", "Bearer " + bearer);
            logger.trace("getting group membership from {}", getGroupMembership.getURI());
            response = httpClient.execute(getGroupMembership, new BasicResponseHandler());

            var groupMembership = parseGroupMembershipResponse(response);
            var nextPage = groupMembership.v1();
            var groups = new ArrayList<>(groupMembership.v2());

            while (nextPage != null) {
                getGroupMembership.setURI(new URI(nextPage));
                logger.trace("getting group membership from {}", getGroupMembership.getURI());
                response = httpClient.execute(getGroupMembership, new BasicResponseHandler());

                groupMembership = parseGroupMembershipResponse(response);
                nextPage = groupMembership.v1();
                groups.addAll(groupMembership.v2());
            }

            logger.trace("Got {} groups from Graph {}", groups.size(), String.join(", ", groups));

            final var userData = new UserRoleMapper.UserData(principal, null, groups, Map.of(), config);

            roleMapper.resolveRoles(userData, listener.delegateFailureAndWrap((l, roles) -> {
                final var user = new User(principal, roles.toArray(Strings.EMPTY_ARRAY), name, email, Map.of(), true);
                logger.debug("Entra ID user {}", user);
                l.onResponse(user);
            }));
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }

    private Tuple<String, String> parseUserInfo(String response) throws ParseException {
        var json = JSONObjectUtils.parse(response);

        var email = (String) json.get("mail");
        var name = (String) json.get("displayName");

        return Tuple.tuple(email, name);
    }

    private Tuple<String, List<String>> parseGroupMembershipResponse(String response) throws ParseException {
        var json = JSONObjectUtils.parse(response);

        var nextLink = (String) json.get("@odata.nextLink");
        var groups = ((List<?>) json.get("value")).stream().map(group -> {
            if (group instanceof Map<?, ?> m) {
                return (String) m.get("id");
            } else {
                return null;
            }
        }).toList();

        return Tuple.tuple(nextLink, groups);
    }
}
