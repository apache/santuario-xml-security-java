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

import java.lang.reflect.Constructor;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.xml.security.Init;
import org.apache.xml.security.keys.KeyInfo;
import org.junit.Assert;

import static org.apache.xml.security.test.stax.utils.KeyLoader.loadPublicKey;
import static org.apache.xml.security.test.stax.utils.KeyLoader.loadXML;

public class DEREncodedKeyValueResolverTest extends Assert {

    private PublicKey rsaKeyControl;
    private PublicKey dsaKeyControl;
    private PublicKey ecKeyControl;

    public DEREncodedKeyValueResolverTest() throws Exception {
        //
        // If the BouncyCastle provider is not installed, then try to load it
        // via reflection.
        //
        if (Security.getProvider("BC") == null) {
            Constructor<?> cons = null;
            try {
                Class<?> c = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
                cons = c.getConstructor(new Class[] {});
            } catch (Exception e) {
                //ignore
            }
            if (cons != null) {
                Provider provider = (Provider)cons.newInstance();
                Security.insertProviderAt(provider, 1);
                ecKeyControl = loadPublicKey("ec.key", "EC");
            }
        }

        rsaKeyControl = loadPublicKey("rsa.key", "RSA");
        dsaKeyControl = loadPublicKey("dsa.key", "DSA");

        if (!Init.isInitialized()) {
            Init.init();
        }
    }

    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        Security.removeProvider("org.bouncycastle.jce.provider.BouncyCastleProvider");
    }

    @org.junit.Test
    public void testRSAPublicKey() throws Exception {
        Document doc = loadXML("DEREncodedKeyValue-RSA.xml");
        Element element = doc.getDocumentElement();

        KeyInfo keyInfo = new KeyInfo(element, "");
        assertEquals(rsaKeyControl, keyInfo.getPublicKey());
    }

    @org.junit.Test
    public void testDSAPublicKey() throws Exception {
        Document doc = loadXML("DEREncodedKeyValue-DSA.xml");
        Element element = doc.getDocumentElement();

        KeyInfo keyInfo = new KeyInfo(element, "");
        assertEquals(dsaKeyControl, keyInfo.getPublicKey());
    }

    @org.junit.Test
    public void testECPublicKey() throws Exception {
        if (ecKeyControl == null) {
            return;
        }

        Document doc = loadXML("DEREncodedKeyValue-EC.xml");
        Element element = doc.getDocumentElement();

        KeyInfo keyInfo = new KeyInfo(element, "");
        assertEquals(ecKeyControl, keyInfo.getPublicKey());
    }
}
