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


import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.keys.KeyInfoEnc;
import org.apache.xml.security.encryption.params.ConcatKDFParams;
import org.apache.xml.security.encryption.params.KeyAgreementParameters;
import org.apache.xml.security.encryption.params.KeyDerivationParameters;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.parser.XMLParserException;
import org.apache.xml.security.testutils.JDKTestUtils;
import org.apache.xml.security.testutils.KeyTestUtils;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.utils.KeyUtils;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;


/**
 *
 */
class XMLCipherBrainpoolTest {

    static {
        org.apache.xml.security.Init.init();
    }
    private final String documentName;
    private final String elementName;
    private final String elementIndex;
    private final String basedir;
    private boolean haveISOPadding;

    private static boolean bcInstalled;

    public XMLCipherBrainpoolTest() throws Exception {
        basedir = System.getProperty("basedir",".");
        documentName = System.getProperty("org.apache.xml.enc.test.doc",
                                          basedir + "/pom.xml");
        elementName = System.getProperty("org.apache.xml.enc.test.elem", "project");
        elementIndex = System.getProperty("org.apache.xml.enc.test.idx", "0");

        // Determine if we have ISO 10126 Padding - needed for Bulk AES or
        // 3DES encryption

        haveISOPadding = false;
        String algorithmId =
            JCEMapper.translateURItoJCEID(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);

        if (algorithmId != null) {
            try {
                if (Cipher.getInstance(algorithmId) != null) {
                    haveISOPadding = true;
                }
            } catch (NoSuchAlgorithmException nsae) {
                //
            } catch (NoSuchPaddingException nspe) {
                //
            }
        }

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
                Security.insertProviderAt(provider, 2);
                bcInstalled = true;
            }
        }
    }

    @AfterAll
    public static void cleanup() throws Exception {
        Security.removeProvider("BC");
    }

    /**
     * Test that encrypt and decrypt using ECDH-ES for key encryption
     * <p/>
     * @throws Exception Thrown when there is any problem in signing or verification
     */
    @ParameterizedTest
    @EnumSource(value = KeyUtils.KeyType.class, mode = EnumSource.Mode.INCLUDE,
            names = {"BRAINPOOLP256R1", "BRAINPOOLP384R1", "BRAINPOOLP512R1"})
    void testAES128ElementEcdhEsKWCipher(KeyUtils.KeyType keyType) throws Exception {
        Assumptions.assumeTrue(bcInstalled);
        // Skip test for IBM JDK
        Assumptions.assumeTrue(haveISOPadding,
                "Test testAES128ElementEcdhEsKWCipher for key ["+keyType+"] was skipped as necessary algorithms not available!" );
        Assumptions.assumeTrue(JDKTestUtils.isAlgorithmSupported(keyType.getAlgorithm().getJceName(), true),
                "Test testAES128ElementEcdhEsKWCipher for key ["+keyType+"] was skipped as necessary algorithms not available!" );

        // init parameters encrypted key object
        String dataEncryptionAlgorithm = XMLCipher.AES_256_GCM;
        String keyWrapAlgorithm = XMLCipher.AES_128_KeyWrap;
        int transportKeyBitLength = 128;

        // prepare the test document
        Document d = document(); // source
        Document ed = null;
        Document dd = null;
        Element e = (Element) d.getElementsByTagName(element()).item(index());
        Element ee = null;
        String source = null;
        String target = null;

        source = toString(d);

        // Generate test recipient key pair
        KeyPair recipientKeyPair = KeyTestUtils.generateKeyPair(keyType);

        PrivateKey privRecipientKey = recipientKeyPair.getPrivate();
        PublicKey pubRecipientKey = recipientKeyPair.getPublic();

        // Generate a traffic key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(transportKeyBitLength);
        Key ephemeralSymmetricKey = keygen.generateKey();


        XMLCipher cipherEncKey = XMLCipher.getInstance(keyWrapAlgorithm);
        cipherEncKey.init(XMLCipher.WRAP_MODE, pubRecipientKey);
        cipherEncKey.setSecureValidation(true);
        // create key agreement parameters
        int keyBitLen = KeyUtils.getAESKeyBitSizeForWrapAlgorithm(keyWrapAlgorithm);
        KeyDerivationParameters keyDerivationParameter = ConcatKDFParams
                .createBuilder(keyBitLen, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256)
                .build();
        AlgorithmParameterSpec parameterSpec = new KeyAgreementParameters(
                KeyAgreementParameters.ActorType.ORIGINATOR,
                EncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES,
                keyDerivationParameter);
        // encrypt transport key with KeyAgreement
        EncryptedKey encryptedKey = cipherEncKey.encryptKey(d, ephemeralSymmetricKey, parameterSpec, null);
        assertEquals(1,  ((KeyInfoEnc)encryptedKey.getKeyInfo()).lengthAgreementMethod());


        // encrypt data
        XMLCipher cipherEncData = XMLCipher.getInstance(dataEncryptionAlgorithm);
        cipherEncData.init(XMLCipher.ENCRYPT_MODE, ephemeralSymmetricKey);
        EncryptedData builder = cipherEncData.getEncryptedData();
        // add encrypted key to key info in encrypted data
        KeyInfo builderKeyInfo = builder.getKeyInfo();
        if (builderKeyInfo == null) {
            builderKeyInfo = new KeyInfo(d);
            builder.setKeyInfo(builderKeyInfo);
        }
        builderKeyInfo.add(encryptedKey);

        ed = cipherEncData.doFinal(d, e);

        Files.write(Paths.get("target","test-enc-"+keyType.name()+".xml"), toString(ed).getBytes());

        //decrypt
        ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
        XMLCipher cipherDecData = XMLCipher.getInstance(dataEncryptionAlgorithm);
        cipherDecData.init(XMLCipher.DECRYPT_MODE, null);
        cipherDecData.setKEK(privRecipientKey);
        cipherDecData.setSecureValidation(true);
        dd = cipherDecData.doFinal(ed, ee);

        target = toString(dd);
        assertEquals(source, target);
    }

    private String toString (Node n) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Canonicalizer c14n = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);

        c14n.canonicalizeSubtree(n, baos);
        baos.flush();

        return baos.toString(StandardCharsets.UTF_8);
    }

    private Document document() throws XMLParserException, IOException {
        File f = new File(documentName);
        return XMLUtils.read(new FileInputStream(f), false);
    }

    private String element() {
        return elementName;
    }

    private int index() {
        return Integer.parseInt(elementIndex);
    }

}
