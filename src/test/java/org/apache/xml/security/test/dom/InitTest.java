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
package org.apache.xml.security.test.dom;


import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.signature.XMLSignature;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class InitTest {

    @BeforeAll
    public static void setup() {
        System.setProperty("org.apache.xml.security.resource.config",
                "org/apache/xml/security/resource/config.xml");
    }

    @AfterAll
    public static void cleanup() {
        System.clearProperty("org.apache.xml.security.resource.config");
    }

    @org.junit.jupiter.api.Test
    public void testFileInit() throws Exception {
        assertFalse(Init.isInitialized());
        Init.init();
        assertTrue(Init.isInitialized());

        // Test that initialization seems to have happened OK
        new SignatureAlgorithm(TestUtils.newDocument(), XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        assertEquals("MessageDigest", JCEMapper.getAlgorithmClassFromURI(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256));
    }

}
