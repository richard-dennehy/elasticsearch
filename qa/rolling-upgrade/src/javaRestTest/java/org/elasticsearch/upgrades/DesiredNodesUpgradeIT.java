/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

package org.elasticsearch.upgrades;

import com.carrotsearch.randomizedtesting.annotations.Name;

import org.elasticsearch.action.admin.cluster.desirednodes.UpdateDesiredNodesRequest;
import org.elasticsearch.client.Request;
import org.elasticsearch.cluster.metadata.DesiredNode;
import org.elasticsearch.cluster.metadata.DesiredNodeWithStatus;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.ByteSizeValue;
import org.elasticsearch.common.xcontent.support.XContentMapValues;
import org.elasticsearch.xcontent.json.JsonXContent;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.elasticsearch.node.Node.NODE_NAME_SETTING;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;

public class DesiredNodesUpgradeIT extends AbstractRollingUpgradeTestCase {

    private final int desiredNodesVersion;

    public DesiredNodesUpgradeIT(@Name("upgradedNodes") int upgradedNodes) {
        super(upgradedNodes);
        desiredNodesVersion = upgradedNodes + 1;
    }

    public void testUpgradeDesiredNodes() throws Exception {
        if (isMixedCluster() || isUpgradedCluster()) {
            final Map<String, Object> desiredNodes = getLatestDesiredNodes();
            final String historyId = extractValue(desiredNodes, "history_id");
            final int version = extractValue(desiredNodes, "version");
            assertThat(historyId, is(equalTo("upgrade_test")));
            assertThat(version, is(equalTo(desiredNodesVersion - 1)));
        }

        addClusterNodesToDesiredNodesWithProcessorsOrProcessorRanges(desiredNodesVersion);
        assertAllDesiredNodesAreActualized();
    }

    private Map<String, Object> getLatestDesiredNodes() throws IOException {
        final var getDesiredNodesRequest = new Request("GET", "/_internal/desired_nodes/_latest");
        final var response = client().performRequest(getDesiredNodesRequest);
        assertThat(response.getStatusLine().getStatusCode(), is(equalTo(200)));
        return responseAsMap(response);
    }

    private void assertAllDesiredNodesAreActualized() throws Exception {
        final var request = new Request("GET", "_cluster/state/metadata");
        final var response = client().performRequest(request);
        assertThat(response.getStatusLine().getStatusCode(), is(equalTo(200)));
        Map<String, Object> responseMap = responseAsMap(response);
        List<Map<String, Object>> nodes = extractValue(responseMap, "metadata.desired_nodes.latest.nodes");
        assertThat(nodes.size(), is(greaterThan(0)));
        for (Map<String, Object> desiredNode : nodes) {
            final int status = extractValue(desiredNode, "status");
            assertThat((short) status, is(equalTo(DesiredNodeWithStatus.Status.ACTUALIZED.getValue())));
        }
    }

    private void addClusterNodesToDesiredNodesWithProcessorsOrProcessorRanges(int version) throws Exception {
        final List<DesiredNode> nodes;
        if (randomBoolean()) {
            nodes = getNodeNames().stream()
                .map(
                    nodeName -> new DesiredNode(
                        Settings.builder().put(NODE_NAME_SETTING.getKey(), nodeName).build(),
                        randomDoubleProcessorCount(),
                        ByteSizeValue.ofGb(randomIntBetween(10, 24)),
                        ByteSizeValue.ofGb(randomIntBetween(128, 256))
                    )
                )
                .toList();
        } else {
            nodes = getNodeNames().stream().map(nodeName -> {
                double minProcessors = randomDoubleProcessorCount();
                return new DesiredNode(
                    Settings.builder().put(NODE_NAME_SETTING.getKey(), nodeName).build(),
                    new DesiredNode.ProcessorsRange(minProcessors, minProcessors + randomIntBetween(10, 20)),
                    ByteSizeValue.ofGb(randomIntBetween(10, 24)),
                    ByteSizeValue.ofGb(randomIntBetween(128, 256))
                );
            }).toList();
        }
        updateDesiredNodes(nodes, version);
    }

    private void updateDesiredNodes(List<DesiredNode> nodes, int version) throws IOException {
        final var request = new Request("PUT", "/_internal/desired_nodes/upgrade_test/" + version);
        try (var builder = JsonXContent.contentBuilder()) {
            builder.startObject();
            builder.xContentList(UpdateDesiredNodesRequest.NODES_FIELD.getPreferredName(), nodes);
            builder.endObject();
            request.setJsonEntity(Strings.toString(builder));
            request.setOptions(
                expectVersionSpecificWarnings(
                    v -> v.compatible("[version removal] Specifying node_version in desired nodes requests is deprecated.")
                )
            );
            final var response = client().performRequest(request);
            final var statusCode = response.getStatusLine().getStatusCode();
            assertThat(statusCode, equalTo(200));
        }
    }

    private List<String> getNodeNames() throws Exception {
        final var request = new Request("GET", "/_nodes");
        final var response = client().performRequest(request);
        Map<String, Object> responseMap = responseAsMap(response);
        Map<String, Map<String, Object>> nodes = extractValue(responseMap, "nodes");
        final List<String> nodeNames = new ArrayList<>();
        for (Map.Entry<String, Map<String, Object>> nodeInfoEntry : nodes.entrySet()) {
            final String nodeName = extractValue(nodeInfoEntry.getValue(), "name");
            nodeNames.add(nodeName);
        }

        return nodeNames;
    }

    private double randomDoubleProcessorCount() {
        return randomDoubleBetween(0.5, 512.1234, true);
    }

    @SuppressWarnings("unchecked")
    private static <T> T extractValue(Map<String, Object> map, String path) {
        return (T) XContentMapValues.extractValue(path, map);
    }
}
