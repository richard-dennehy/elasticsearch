/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.cloud;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.ActionType;
import org.elasticsearch.client.internal.Client;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.core.Nullable;
import org.elasticsearch.xpack.core.ClientHelper;

import java.util.Map;
import java.util.function.BiConsumer;

public class CloudCredentialClientHelper {
    private CloudCredentialClientHelper() {}

    public static <Request extends ActionRequest, Response extends ActionResponse> void executeWithHeadersAsync(
        Map<String, String> headers,
        String origin,
        Client client,
        ActionType<Response> action,
        Request request,
        InternalCloudApiKeyService cloudApiKeyService,
        @Nullable CloudCredential cloudCredential,
        ActionListener<Response> listener
    ) {
        if (cloudCredential == null) {
            ClientHelper.executeWithHeadersAsync(headers, origin, client, action, request, listener);
            return;
        }

        var threadContext = client.threadPool().getThreadContext();
        ClientHelper.executeWithHeadersAsync(threadContext, headers, origin, request, listener, (r, l) -> {
            cloudApiKeyService.injectCloudManagedCredential(threadContext, cloudCredential);
            client.execute(action, r, l);
        });
    }

    public static <Request, Response> void executeWithHeadersAsync(
        ThreadContext threadContext,
        Map<String, String> headers,
        String origin,
        Request request,
        ActionListener<Response> listener,
        InternalCloudApiKeyService cloudApiKeyService,
        @Nullable CloudCredential cloudCredential,
        BiConsumer<Request, ActionListener<Response>> consumer
    ) {
        if (cloudCredential == null) {
            ClientHelper.executeWithHeadersAsync(threadContext, headers, origin, request, listener, consumer);
            return;
        }

        ClientHelper.executeWithHeadersAsync(threadContext, headers, origin, request, listener, (r, l) -> {
            cloudApiKeyService.injectCloudManagedCredential(threadContext, cloudCredential);
            consumer.accept(r, l);
        });
    }
}
