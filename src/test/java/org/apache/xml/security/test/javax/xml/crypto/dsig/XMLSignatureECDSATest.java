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

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.testutils.JDKTestUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Unit test for javax.xml.crypto.dsig.XMLSignature creation. Some of the algorithms
 * using SHA3 are supported from JDK 16+ and require AuxiliaryProvider (BouncyCastle)
 * provider to be activated.
 * @see <A HREF="https://www.oracle.com/java/technologies/javase/16-relnote-issues.html">
 *     SunPKCS11 Provider Supports SHA-3 Related Algorithms </A>
 *
 * <p />
 * To execute just this tests class run the following command:
 * (for JDK16+ you can skip the profile "bouncycastle"
 * <code>mvn test -Dtest=XMLSignatureECDSATest -P bouncycastle</code>
 * or to test it during the build start the project with the profile "bouncycastle"
 * <code>mvn clean install -P bouncycastle</code>
 */
class XMLSignatureECDSATest extends XMLSignatureAbstract {
    protected static final System.Logger LOG = System.getLogger(XMLSignatureECDSATest.class.getName());
    // Define the KeyStore type
    public static final String KEYSTORE_TYPE = "JKS";
    private static final String KEYSTORE_PATH =
            "src/test/resources/org/apache/xml/security/samples/input/ecdsa.jks";
    private static final String KEYSTORE_AND_KEY_PASSWORD = "security";

    @BeforeAll
    static void initProvider() {
        Assumptions.assumeFalse("IBM Corporation".equals(System.getProperty("java.vendor")), "Skip for IBM JDK");
        Security.insertProviderAt(new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);

        JDKTestUtils.registerAuxiliaryProvider();
    }

    @AfterAll
    static void removeProvider() {
        Security.removeProvider(org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI.class.getName());
        JDKTestUtils.unregisterAuxiliaryProvider();
    }

    @Override
    KeyStore getKeyStore() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        keyStore.load(Files.newInputStream(Paths.get(KEYSTORE_PATH)), KEYSTORE_AND_KEY_PASSWORD.toCharArray());
        return keyStore;
    }

    @Override
    char[] getKeyPassword() {
        return KEYSTORE_AND_KEY_PASSWORD.toCharArray();
    }

    @ParameterizedTest
    @CsvSource(
            {"http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-224, secp256r1",
                    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1, secp256r1",
                    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224, secp256r1",
                    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256, secp256r1",
                    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384, secp256r1",
                    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512, secp256r1",
                    "http://www.w3.org/2007/05/xmldsig-more#ecdsa-ripemd160, secp256r1",
                    // support for SHA3 since jdk 16+
                    "http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-224, secp256r1",
                    "http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-256, secp256r1",
                    "http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-384, secp256r1",
                    "http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-512, secp256r1"
            })
    void createECDSASignatureTest(String signatureAlgorithmURI, String alias) throws Exception {
        String jceAlg = JCEMapper.translateURItoJCEID(signatureAlgorithmURI);
        Assertions.assertNotNull(jceAlg, "The JCE algorithm for [" + signatureAlgorithmURI + "] must not be null!");
        Assumptions.assumeTrue(JDKTestUtils.isAlgorithmSupported(jceAlg, true),
                "The test for ECDSA Signature with JCE algorithm [" + jceAlg
                        + "] was skipped as necessary algorithms not available!");

        byte[] buff = doSignWithJcpApi(signatureAlgorithmURI, alias, false);
        if (LOG.isLoggable(System.Logger.Level.DEBUG)) {
            Files.write(Paths.get("target", "test-ecdsa-" + jceAlg + ".xml"), buff);
        }
        Assertions.assertNotNull(buff);
        assertValidSignatureWithJcpApi(buff, false);
    }
}
