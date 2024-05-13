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
package org.apache.xml.security.test.dom.encryption;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;

import org.w3c.dom.Document;

import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.params.ConcatKDFParams;
import org.apache.xml.security.encryption.params.KeyAgreementParameters;
import org.apache.xml.security.encryption.params.KeyDerivationParameters;
import org.apache.xml.security.testutils.JDKTestUtils;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.utils.KeyUtils;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * This is a test class  for the KeyAgreement algorithm with Brainpool curves.
 * The test uses the AuxiliaryProvider (BouncyCastle) to provide the necessary
 * algorithms.
 * <p />
 * To execute just this tests class run the following command (note the profile):
 * <code>mvn test -Dtest=XMLEncryption11BrainpoolTest -P bouncycastle</code>
 * or to test it during the build start the project with the profile "bouncycastle"
 * <code>mvn clean install -P bouncycastle</code>
 */
class XMLEncryption11BrainpoolTest extends XMLEncryption11TestAbstract{
    protected static final System.Logger LOG = System.getLogger(XMLEncryption11BrainpoolTest.class.getName());

    @BeforeAll
    static void initProvider() {
        Assumptions.assumeTrue(JDKTestUtils.getAuxiliaryProvider() != null, "BouncyCastle is required for this test");
        Assumptions.assumeFalse("IBM Corporation".equals(System.getProperty("java.vendor")), "Skip for IBM JDK" );
        Security.insertProviderAt(JDKTestUtils.getAuxiliaryProvider(), 1);
    }

    @AfterAll
    static void removeProvider() {
        if (JDKTestUtils.getAuxiliaryProvider()!=null) {
            Security.removeProvider(JDKTestUtils.getAuxiliaryProvider().getName());
        }
    }

    /**
     * The KeyAgreement test cases from the W3C test suite using bytearray as input.
     *
     * <a href="https://www.w3.org/2008/xmlsec/Drafts/xmlenc-core-11/test-cases/#sec-KeyAgreement">
     *     xmlenc-core-11 test-cases</a>
     */
    @ParameterizedTest
    @CsvSource({
            "1. brainpoolP256r1, binary-data.hex, ecbrainpool.p12, PKCS12, security, brainpoolP256r1," +
                    " http://www.w3.org/2001/04/xmlenc#kw-aes128, http://www.w3.org/2009/xmlenc11#aes128-gcm," +
                    " http://www.w3.org/2001/04/xmlenc#sha256",
            "2. brainpoolP384r1, binary-data.hex, ecbrainpool.p12, PKCS12, security, brainpoolP384r1," +
                    " http://www.w3.org/2001/04/xmlenc#kw-aes128, http://www.w3.org/2009/xmlenc11#aes128-gcm," +
                    "  http://www.w3.org/2001/04/xmlenc#sha256",
            "3. brainpoolP512r1, binary-data.hex, ecbrainpool.p12, PKCS12, security, brainpoolP512r1," +
                    " http://www.w3.org/2001/04/xmlenc#kw-aes128, http://www.w3.org/2009/xmlenc11#aes128-gcm," +
                    " http://www.w3.org/2001/04/xmlenc#sha256",
    })
    void testAgreementKeyEncryptDecryptDataWithBrainpool(String w3cTag,
                                                         String resourceHexFileName,
                                                         String keystoreFile, String keystoreType,
                                                         String passwd, String alias,
                                                         String keyWrapAlgorithm,
                                                         String encryptionAlgorithm,
                                                         String kdfAlgorithm) throws Exception {
        Assumptions.assumeTrue(haveISOPadding,
                "Skipping testAgreementKey ["+w3cTag+"] as necessary crypto algorithms are not available");

        // Load the keystore
        String resourceFolder = "/org/apache/xml/security/samples/input/";
        KeyStore keyStore = loadKeyStoreFromResource(resourceFolder, keystoreFile, passwd, keystoreType);
        Certificate cert = keyStore.getCertificate(alias);

        KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry(alias, new KeyStore.PasswordProtection(passwd.toCharArray()));
        PrivateKey ecKey = pkEntry.getPrivateKey();

        // Perform encryption
        byte[] testData = hexFileContentByteArray(resourceHexFileName);
        // create empty document for EncryptedKey
        Document doc = DEFAULT_DOCUMENT_BUILDER_FACTORY.newDocumentBuilder().newDocument();

        Key sessionKey = getSessionKey(encryptionAlgorithm);

        int keyBitLen = KeyUtils.getAESKeyBitSizeForWrapAlgorithm(keyWrapAlgorithm);
        KeyDerivationParameters keyDerivationParameter =  ConcatKDFParams
                .createBuilder(keyBitLen, kdfAlgorithm)
                .build();
        AlgorithmParameterSpec parameterSpec = new KeyAgreementParameters(
                KeyAgreementParameters.ActorType.ORIGINATOR,
                EncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES,
                keyDerivationParameter);

        EncryptedKey encryptedKey =
                createEncryptedKey(
                        doc,
                        (X509Certificate)cert,
                        sessionKey,
                        keyWrapAlgorithm,
                        parameterSpec, null);

        doc = encryptData(
                doc,
                encryptedKey,
                sessionKey,
                encryptionAlgorithm,
                new ByteArrayInputStream(testData)
        );

        if (LOG.isLoggable(System.Logger.Level.DEBUG)) {
            Files.write(Paths.get("target","test-enc-"+w3cTag+".xml"), toString(doc.getFirstChild()).getBytes());
            XMLUtils.outputDOM(doc.getFirstChild(), System.out);
        }
        // Perform decryption
        byte[] result  = decryptData(doc, ecKey, (X509Certificate)cert);

        assertNotNull(result);
        assertArrayEquals(testData, result);
    }
}
