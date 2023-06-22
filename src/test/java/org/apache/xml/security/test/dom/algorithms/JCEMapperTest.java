/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.xml.security.test.dom.algorithms;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

class JCEMapperTest {

    static {
        org.apache.xml.security.Init.init();
    }

    @Test
    void testSHA1() {
        assertEquals("MessageDigest", JCEMapper.getAlgorithmClassFromURI(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1));
        assertEquals("SHA-1", JCEMapper.translateURItoJCEID(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1));
    }

    @Test
    void testConcurrency() throws InterruptedException {

        CompletableFuture<Void> futureForProviderA = CompletableFuture.runAsync(() -> {
            final String providerToUse = "ProviderA";
            JCEMapper.setProviderId(providerToUse);
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
            assertEquals(providerToUse, JCEMapper.getProviderId());
        });

        CompletableFuture<Void> futureForProviderB = CompletableFuture.runAsync(() -> {
            final String providerToUse = "ProviderB";
            JCEMapper.setProviderId(providerToUse);
            assertEquals(providerToUse, JCEMapper.getProviderId());
        });

        try {
            futureForProviderA.get();
            futureForProviderB.get();
        } catch (ExecutionException e) {
            fail(e.getCause().getMessage());
        }
    }

}