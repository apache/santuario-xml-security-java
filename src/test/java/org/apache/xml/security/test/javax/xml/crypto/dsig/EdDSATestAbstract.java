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

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.Provider;
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
public abstract class EdDSATestAbstract extends XMLSignatureAbstract {

    public static final String EDDSA_KS =
            "src/test/resources/org/apache/xml/security/samples/input/eddsa.p12";
    public static final String EDDSA_KS_PASSWORD = "security";
    public static final String EDDSA_KS_TYPE = "PKCS12";
    private static boolean bcAddedForTheTest = false;

    private static boolean edDSASupported = true;

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

        if (isNotJDK15up && Security.getProvider("BC") == null) {
            // Use reflection to add new BouncyCastleProvider
            try {
                Class<?> bouncyCastleProviderClass = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
                Provider bouncyCastleProvider = (Provider)bouncyCastleProviderClass.getConstructor().newInstance();
                Security.addProvider(bouncyCastleProvider);
            } catch (ReflectiveOperationException e) {
                // BouncyCastle not installed, ignore
                edDSASupported = false;
            }
            bcAddedForTheTest = true;
        }
    }

    @AfterAll
    public static void afterAll() {
        if (bcAddedForTheTest) {
            Security.removeProvider("BC");
        }
    }

    @Override
    KeyStore getKeyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(EDDSA_KS_TYPE);
        keyStore.load(Files.newInputStream(Paths.get(EDDSA_KS)), EDDSA_KS_PASSWORD.toCharArray());
        return keyStore;
    }

    @Override
    char[] getKeyPassword() {
        return EDDSA_KS_PASSWORD.toCharArray();
    }

    public static boolean isEdDSASupported() {
        return edDSASupported;
    }
}
