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
package org.apache.xml.security.test.dom.keys.keyresolver;

import java.security.PublicKey;

import org.apache.xml.security.Init;
import org.apache.xml.security.keys.KeyInfo;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.apache.xml.security.test.stax.utils.KeyLoader.loadPublicKey;
import static org.apache.xml.security.test.stax.utils.KeyLoader.loadXML;
import static org.junit.jupiter.api.Assertions.assertEquals;

class DEREncodedKeyValueResolverTest {

    private final PublicKey rsaKeyControl;
    private final PublicKey dsaKeyControl;
    private final PublicKey ecKeyControl;

    public DEREncodedKeyValueResolverTest() throws Exception {

        rsaKeyControl = loadPublicKey("rsa.key", "RSA");
        dsaKeyControl = loadPublicKey("dsa.key", "DSA");
        ecKeyControl = loadPublicKey("ec.key", "EC");

        if (!Init.isInitialized()) {
            Init.init();
        }
    }

    @Test
    void testRSAPublicKey() throws Exception {
        Document doc = loadXML("DEREncodedKeyValue-RSA.xml");
        Element element = doc.getDocumentElement();

        KeyInfo keyInfo = new KeyInfo(element, "");
        assertEquals(rsaKeyControl, keyInfo.getPublicKey());
    }

    @Test
    void testDSAPublicKey() throws Exception {
        Document doc = loadXML("DEREncodedKeyValue-DSA.xml");
        Element element = doc.getDocumentElement();

        KeyInfo keyInfo = new KeyInfo(element, "");
        assertEquals(dsaKeyControl, keyInfo.getPublicKey());
    }

    @Test
    void testECPublicKey() throws Exception {
        Document doc = loadXML("DEREncodedKeyValue-EC.xml");
        Element element = doc.getDocumentElement();

        KeyInfo keyInfo = new KeyInfo(element, "");
        assertEquals(ecKeyControl, keyInfo.getPublicKey());
    }
}