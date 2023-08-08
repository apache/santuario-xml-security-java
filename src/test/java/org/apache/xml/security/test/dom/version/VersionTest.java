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
package org.apache.xml.security.test.dom.version;


import java.security.Provider;
import java.security.Security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Version test.
 */
class VersionTest {

    /**
     * A unit test for the algorithm below to convert a version number
     * to a double.
     */
    @Test
    void testRemoveClassifier() throws Exception {
        String version = removeClassifier("1.4.4");
        assertEquals("1.4.4", version);

        version = removeClassifier("1.4.4-SNAPSHOT");
        assertEquals("1.4.4", version);

        version = removeClassifier("1.4");
        assertEquals("1.4", version);
    }

    @Test
    void testVersion() throws Exception {
        Provider provider = Security.getProvider("ApacheXMLDSig");
        if (provider != null) {
            Security.removeProvider(provider.getName());
        }
        Security.addProvider(new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());

        provider = Security.getProvider("ApacheXMLDSig");
        assertNotNull(provider);

        String version = removeClassifier(System.getProperty("product.version"));
        assertEquals(version, provider.getVersionStr());
        assertTrue(provider.getInfo().contains("Santuario"));
    }

    private String removeClassifier(String version) {
        if (version == null) {
            return null;
        }
        // Remove the "-SNAPSHOT" version if it exists
        int dash = version.indexOf('-');
        return dash == -1 ? version : version.substring(0, dash);
    }
}
