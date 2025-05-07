/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authc.saml;

import com.sun.net.httpserver.HttpServer;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.io.Streams;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.rest.RestUtils;
import org.elasticsearch.xcontent.XContentBuilder;
import org.elasticsearch.xcontent.XContentType;
import org.junit.rules.ExternalResource;

import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

public class AzureGraphHttpFixture extends ExternalResource {

    private static final Logger logger = LogManager.getLogger(AzureGraphHttpFixture.class);

    private final String tenantId;
    private final String clientId;
    private final String clientSecret;
    private final String principal;

    private HttpServer server;

    public AzureGraphHttpFixture(String tenantId, String clientId, String clientSecret, String principal) {
        this.tenantId = tenantId;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.principal = principal;
    }

    @Override
    protected void before() throws Throwable {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/" + tenantId + "/oauth2/v2.0/token", exchange -> {
            if (exchange.getRequestMethod().equals("POST") == false) {
                logger.warn("Unsupported HTTP request: {}", exchange.getRequestMethod());
            }

            final var requestBody = Streams.copyToString(new InputStreamReader(exchange.getRequestBody(), Charset.defaultCharset()));
            final var queryParams = new HashMap<String, String>();
            RestUtils.decodeQueryString(requestBody, 0, queryParams);

            if (queryParams.get("grant_type").equals("client_credentials") == false) {
                logger.warn("Invalid Grant Type: {}", queryParams.get("grant_type"));
            }
            if (queryParams.get("client_id").equals(clientId) == false) {
                logger.warn("Invalid Client ID: {}", queryParams.get("client_id"));
            }
            if (queryParams.get("client_secret").equals(clientSecret) == false) {
                logger.warn("Invalid Client Secret: {}", queryParams.get("client_secret"));
            }
            if (queryParams.get("scope").equals("https://graph.microsoft.com/.default") == false) {
                logger.warn("Invalid Scopes: {}", queryParams.get("scope"));
            }

            final var xcb = XContentBuilder.builder(XContentType.JSON.xContent());
            xcb.startObject();
            xcb.field("access_token", "jwt goes here");
            xcb.field("expires_in", 86400L);
            xcb.field("ext_expires_in", 86400L);
            xcb.field("token_type", "Bearer");
            xcb.endObject();

            var responseBytes = BytesReference.bytes(xcb);

            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(RestStatus.OK.getStatus(), responseBytes.length());
            responseBytes.writeTo(exchange.getResponseBody());
            exchange.close();
        });
        server.createContext("/v1.0/users/" + principal + "/memberOf/microsoft.graph.group", exchange -> {
            if (exchange.getRequestMethod().equals("GET") == false) {
                logger.warn("Unsupported HTTP request: {}", exchange.getRequestMethod());
            }

            if (exchange.getRequestHeaders().getFirst("Authorization").equals("Bearer jwt goes here") == false) {
                logger.warn("Invalid Authorization header: {}", exchange.getRequestHeaders().getFirst("Authorization"));
            }

            String nextLink = null;
            var groups = new Object[] { Map.of("id", "group-id-1"), Map.of("id", "group-id-2") };

            if (exchange.getRequestURI().getQuery().contains("$skiptoken")) {
                groups = new Object[] { Map.of("id", "group-id-3") };
            } else {
                nextLink = getBaseUrl() + exchange.getRequestURI().toString() + "&$skiptoken=fake_skip_token";
            }

            final var responseJson = XContentBuilder.builder(XContentType.JSON.xContent());
            responseJson.startObject();
            responseJson.field("@odata.nextLink", nextLink);
            responseJson.array("value", groups);
            responseJson.endObject();

            var responseBytes = BytesReference.bytes(responseJson);

            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(RestStatus.OK.getStatus(), responseBytes.length());
            responseBytes.writeTo(exchange.getResponseBody());

            exchange.close();
        });
        server.start();
    }

    public String getBaseUrl() {
        return "http://" + server.getAddress().getHostString() + ":" + server.getAddress().getPort();
    }

    @Override
    protected void after() {
        server.stop(0);
    }
}
