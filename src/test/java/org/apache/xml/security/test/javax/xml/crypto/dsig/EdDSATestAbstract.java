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
package org.apache.xml.security.test.javax.xml.crypto.dsig;

import java.security.Security;

import javax.xml.crypto.dsig.dom.DOMValidateContext;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * Abstract/super class for EdDSA signature tests
 */
public abstract class EdDSATestAbstract {

    public static final String EDDSA_KS =
            "src/test/resources/org/apache/xml/security/samples/input/eddsa.p12";
    public static final String EDDSA_KS_PASSWORD = "security";
    public static final String EDDSA_KS_TYPE = "PKCS12";
    private static boolean bcAddedForTheTest = false;

    @BeforeAll
    public static void beforeAll() {
        Security.insertProviderAt
                (new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
        // Since JDK 15, the EdDSA algorithms are supported in the default java JCA provider.
        // Add BouncyCastleProvider only for java versions before JDK 15.
        boolean isNotJDK15up;
        try {
            int javaVersion = Integer.getInteger("java.specification.version", 0);
            isNotJDK15up = javaVersion < 15;
        } catch (NumberFormatException ex) {
            isNotJDK15up = true;
        }
        if (isNotJDK15up && Security.getProvider(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            bcAddedForTheTest = true;
        }
    }

    @AfterAll
    public static void afterAll() {
        if (bcAddedForTheTest) {
            Security.removeProvider(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME);
        }
    }

    public void updateIdReferences(DOMValidateContext vc, String elementName, String idAttributeName) {
        Document doc = vc.getNode().getOwnerDocument();
        NodeList nl = doc.getElementsByTagName(elementName);
        vc.setIdAttributeNS((Element) nl.item(0), null, idAttributeName);
    }
}
