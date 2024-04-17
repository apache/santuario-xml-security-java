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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;

import org.apache.xml.security.testutils.JDKTestUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Unit test for brainpool javax.xml.crypto.dsig.XMLSignature creation. The tests
 * require BouncyCastle provider to be activated. Please note also the setting of
 * the DOMSignContext property "org.jcp.xml.dsig.internal.dom.SignatureProvider" to
 * provide signature provider for the XMLSignature creation. SunJCE provider does
 * not support brainpool curves signatures from JDK 15+
 * <p />
 * To execute just this tests class run the following command:
 * <code>mvn test -Dtest=XMLSignatureBrainpoolTest -P bouncycastle</code>
 * or to test it during the build start the project with the profile "bouncycastle"
 * <code>mvn clean install -P bouncycastle</code>
 */
class XMLSignatureBrainpoolTest  extends XMLSignatureAbstract {
    protected static final System.Logger LOG = System.getLogger(XMLSignatureBrainpoolTest.class.getName());

    private static final String ECDSA_KS_PATH =
            "src/test/resources/org/apache/xml/security/samples/input/ecbrainpool.p12";
    private static final String ECDSA_KS_PASSWORD = "security";
    public static final String ECDSA_KS_TYPE = "PKCS12";


    @BeforeAll
    static void initProvider() {
        Assumptions.assumeTrue(JDKTestUtils.getAuxiliaryProvider() != null, "BouncyCastle is required for this test");
        Assumptions.assumeFalse("IBM Corporation".equals(System.getProperty("java.vendor")), "Skip for IBM JDK" );

        Security.insertProviderAt(new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    @AfterAll
    static void removeProvider() {
        Security.removeProvider(org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI.class.getName());
    }

    @Override
    KeyStore getKeyStore() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance(ECDSA_KS_TYPE);
        keyStore.load(Files.newInputStream(Paths.get(ECDSA_KS_PATH)), ECDSA_KS_PASSWORD.toCharArray());
        return keyStore;
    }

    @Override
    char[] getKeyPassword() {
        return ECDSA_KS_PASSWORD.toCharArray();
    }

    @ParameterizedTest
    @CsvSource({"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256, brainpoolP256r1",
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256, brainpoolP384r1",
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256, brainpoolP512r1"
    })
    void createEdDSASignatureTest(String signatureAlgorithm, String alias) throws Exception {
        byte[] buff = doSignWithJcpApi(signatureAlgorithm, alias, true);
        if (LOG.isLoggable(System.Logger.Level.DEBUG)) {
            Files.write(Paths.get("target","test-sign-"+alias+".xml"), buff);
        }
        Assertions.assertNotNull(buff);
        assertValidSignatureWithJcpApi(buff, true);
    }
}
