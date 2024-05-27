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
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.encryption.CipherData;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.EncryptionMethod;
import org.apache.xml.security.encryption.EncryptionProperties;
import org.apache.xml.security.encryption.EncryptionProperty;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLCipherUtil;
import org.apache.xml.security.encryption.keys.KeyInfoEnc;
import org.apache.xml.security.encryption.params.ConcatKDFParams;
import org.apache.xml.security.encryption.params.HKDFParams;
import org.apache.xml.security.encryption.params.KeyAgreementParameters;
import org.apache.xml.security.encryption.params.KeyDerivationParameters;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.KeyName;
import org.apache.xml.security.parser.XMLParserException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.testutils.JDKTestUtils;
import org.apache.xml.security.testutils.KeyTestUtils;
import org.apache.xml.security.transforms.params.XPathContainer;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.utils.KeyUtils;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assumptions.assumeFalse;


/**
 *
 */
class XMLCipherTest {

    private static final Logger LOG = System.getLogger(XMLCipherTest.class.getName());

    static {
        org.apache.xml.security.Init.init();
    }

    private final String documentName;
    private final String elementName;
    private final String elementIndex;
    private XMLCipher cipher;
    private final String basedir;
    private boolean haveISOPadding;
    private final boolean haveKeyWraps;
    private final String tstBase64EncodedString;
    private boolean bcInstalled;

    private final boolean isIBMJdK = System.getProperty("java.vendor").contains("IBM");

    public XMLCipherTest() throws Exception {
        basedir = System.getProperty("basedir",".");
        documentName = System.getProperty("org.apache.xml.enc.test.doc",
                                          basedir + "/pom.xml");
        elementName = System.getProperty("org.apache.xml.enc.test.elem", "project");
        elementIndex = System.getProperty("org.apache.xml.enc.test.idx", "0");

        tstBase64EncodedString =
            "YmNkZWZnaGlqa2xtbm9wcRrPXjQ1hvhDFT+EdesMAPE4F6vlT+y0HPXe0+nAGLQ8";

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

        haveKeyWraps =
            JCEMapper.translateURItoJCEID(EncryptionConstants.ALGO_ID_KEYWRAP_AES128) != null;
    }

    @AfterEach
    public void afterTest() throws Exception {
        // remove the dynamically installed provider
        if (JDKTestUtils.getAuxiliaryProvider()!=null) {
            Security.removeProvider(JDKTestUtils.getAuxiliaryProvider().getName());
        }
    }
    /**
     * Test encryption using a generated AES 128 bit key that is
     * encrypted using a AES 192 bit key.  Then reverse using the KEK
     */
    @Test
    void testAES128ElementAES192KWCipherUsingKEK() throws Exception {

        Document d = document(); // source
        Document ed = null;
        Document dd = null;
        Element e = (Element) d.getElementsByTagName(element()).item(index());
        Element ee = null;

        String source = null;
        String target = null;

        if (haveISOPadding && haveKeyWraps) {
            source = toString(d);

            // Set up a Key Encryption Key
            byte[] bits192 = "abcdefghijklmnopqrstuvwx".getBytes();
            Key kek = new SecretKeySpec(bits192, "AES");

            // Generate a traffic key
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(128);
            Key key = keygen.generateKey();

            cipher = XMLCipher.getInstance(XMLCipher.AES_192_KeyWrap);
            cipher.init(XMLCipher.WRAP_MODE, kek);
            cipher.setSecureValidation(true);
            EncryptedKey encryptedKey = cipher.encryptKey(d, key);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_128);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
            EncryptedData builder = cipher.getEncryptedData();

            KeyInfo builderKeyInfo = builder.getKeyInfo();
            if (builderKeyInfo == null) {
                builderKeyInfo = new KeyInfo(d);
                builder.setKeyInfo(builderKeyInfo);
            }

            builderKeyInfo.add(encryptedKey);

            ed = cipher.doFinal(d, e);

            //decrypt
            key = null;
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
            cipher = XMLCipher.getInstance(XMLCipher.AES_128);
            cipher.init(XMLCipher.DECRYPT_MODE, null);
            cipher.setKEK(kek);
            cipher.setSecureValidation(true);
            dd = cipher.doFinal(ed, ee);

            target = toString(dd);
            assertEquals(source, target);
        } else {
            LOG.log(Level.WARNING,
                "Test testAES128ElementAES192KWCipherUsingKEK skipped as "
                + "necessary algorithms not available"
            );
        }
    }

    /**
     * Test encryption using a generated AES 256 bit key that is
     * encrypted using an RSA key.  Reverse using KEK
     */
    @Test
    void testAES256ElementRSAKWCipherUsingKEK() throws Exception {

        Document d = document(); // source
        Document ed = null;
        Document dd = null;
        Element e = (Element) d.getElementsByTagName(element()).item(index());
        Element ee = null;

        String source = null;
        String target = null;

        if (haveISOPadding) {
            source = toString(d);

            // Generate an RSA key
            KeyPairGenerator rsaKeygen = KeyPairGenerator.getInstance("RSA");
            KeyPair kp = rsaKeygen.generateKeyPair();
            PrivateKey priv = kp.getPrivate();
            PublicKey pub = kp.getPublic();

            // Generate a traffic key
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(256);
            Key key = keygen.generateKey();


            cipher = XMLCipher.getInstance(XMLCipher.RSA_v1dot5);
            cipher.init(XMLCipher.WRAP_MODE, pub);
            cipher.setSecureValidation(true);
            EncryptedKey encryptedKey = cipher.encryptKey(d, key);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_256);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
            EncryptedData builder = cipher.getEncryptedData();

            KeyInfo builderKeyInfo = builder.getKeyInfo();
            if (builderKeyInfo == null) {
                builderKeyInfo = new KeyInfo(d);
                builder.setKeyInfo(builderKeyInfo);
            }

            builderKeyInfo.add(encryptedKey);

            ed = cipher.doFinal(d, e);
            LOG.log(Level.DEBUG, "Encrypted document");
            LOG.log(Level.DEBUG, toString(ed));


            //decrypt
            key = null;
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
            cipher = XMLCipher.getInstance(XMLCipher.AES_256);
            cipher.init(XMLCipher.DECRYPT_MODE, null);
            cipher.setKEK(priv);
            cipher.setSecureValidation(true);
            dd = cipher.doFinal(ed, ee);

            target = toString(dd);
            assertEquals(source, target);
        } else {
            LOG.log(Level.WARNING,
                "Test testAES256ElementRSAKWCipherUsingKEK skipped as "
                + "necessary algorithms not available"
            );
        }
    }

    /**
     * Test that encrypt and decrypt using ECDH-ES for key encryption
     * <p/>
     * @throws Exception Thrown when there is any problem in signing or verification
     */
    @ParameterizedTest
    @EnumSource(value = KeyUtils.KeyType.class, mode = EnumSource.Mode.INCLUDE,
            names = {"SECP256R1", "SECP384R1", "SECP521R1", "X25519", "X448"})
    void testAES128ElementEcdhEsKWCipher(KeyUtils.KeyType keyType) throws Exception {
        // Skip test for IBM JDK
        Assumptions.assumeTrue(haveISOPadding,
                "Test testAES128ElementEcdhEsKWCipher for key [" + keyType + "] was skipped as necessary algorithms not available!");
        Assumptions.assumeTrue(JDKTestUtils.isAlgorithmSupported(keyType.getAlgorithm().getJceName(), true),
                "Test testAES128ElementEcdhEsKWCipher for key [" + keyType + "] was skipped as necessary algorithms not available!");

        // init parameters encrypted key object
        String dataEncryptionAlgorithm = XMLCipher.AES_256_GCM;
        String keyWrapAlgorithm = XMLCipher.AES_128_KeyWrap;
        int transportKeyBitLength = 128;
        String keyAgreementMethod;
        switch (keyType) {
            case X25519:
                keyAgreementMethod = EncryptionConstants.ALGO_ID_KEYAGREEMENT_X25519;
                break;
            case X448:
                keyAgreementMethod = EncryptionConstants.ALGO_ID_KEYAGREEMENT_X448;
                break;
            default:
                keyAgreementMethod = EncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES;
                break;
        }

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
                keyAgreementMethod,
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

    @ParameterizedTest
    @EnumSource(value = KeyUtils.KeyType.class, mode = EnumSource.Mode.INCLUDE,
            names = {"SECP256R1", "SECP384R1", "SECP521R1", "X25519", "X448"})
    void testAES128ElementEcdhEsKWCipherHKDF(KeyUtils.KeyType keyType) throws Exception {
        // Skip test for IBM JDK
        Assumptions.assumeTrue(haveISOPadding,
                "Test testAES128ElementEcdhEsKWCipher for key [" + keyType + "] was skipped as necessary algorithms not available!");
        Assumptions.assumeTrue(JDKTestUtils.isAlgorithmSupported(keyType.getAlgorithm().getJceName(), true),
                "Test testAES128ElementEcdhEsKWCipher for key [" + keyType + "] was skipped as necessary algorithms not available!");

        // init parameters encrypted key object
        String dataEncryptionAlgorithm = XMLCipher.AES_256_GCM;
        String keyWrapAlgorithm = XMLCipher.AES_128_KeyWrap;
        int transportKeyBitLength = 128;
        String keyAgreementMethod;
        switch (keyType) {
            case X25519:
                keyAgreementMethod = EncryptionConstants.ALGO_ID_KEYAGREEMENT_X25519;
                break;
            case X448:
                keyAgreementMethod = EncryptionConstants.ALGO_ID_KEYAGREEMENT_X448;
                break;
            default:
                keyAgreementMethod = EncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES;
                break;
        }

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
        HKDFParams keyDerivationParameter = HKDFParams.createBuilder(keyBitLen,
                XMLSignature.ALGO_ID_MAC_HMAC_SHA256)
                .salt(SecureRandom.getSeed(32))
                .info("test-info-data".getBytes(StandardCharsets.UTF_8))
                .build();

        AlgorithmParameterSpec parameterSpec = new KeyAgreementParameters(
                KeyAgreementParameters.ActorType.ORIGINATOR,
                keyAgreementMethod,
                keyDerivationParameter);
        // encrypt transport key with KeyAgreement
        EncryptedKey encryptedKey = cipherEncKey.encryptKey(d, ephemeralSymmetricKey, parameterSpec, null);
        assertEquals(1, ((KeyInfoEnc) encryptedKey.getKeyInfo()).lengthAgreementMethod());
        KeyName keyName = new KeyName(d, "test-key-name");
        ((KeyInfoEnc) encryptedKey.getKeyInfo()).itemAgreementMethod(0).getRecipientKeyInfo().add(keyName);


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

        org.apache.xml.security.test.javax.xml.crypto.dsig.TestUtils.validateSecurityOrEncryptionElement(ed.getDocumentElement());

        Files.write(Paths.get("target", "test-ka-dh-hkdf-" + keyType.name() + ".xml"), toString(ed).getBytes());

        //decrypt
        ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
        XMLCipher cipherDecData = XMLCipher.getInstance(dataEncryptionAlgorithm);
        cipherDecData.init(XMLCipher.DECRYPT_MODE, null);
        cipherDecData.setKEK(privRecipientKey);
        cipherDecData.setSecureValidation(true);
        dd = cipherDecData.doFinal(ed, ee);

        target = toString(dd);
        assertNotNull(target);
        assertEquals(source, target);
    }

    /**
     * The http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p identifier defines the
     * mask generation function as the fixed value of MGF1 with SHA1. In this case
     * the optional xenc11:MGF element of the xenc:EncryptionMethod element
     * MUST NOT be provided. For the http://www.w3.org/2009/xmlenc11#rsa-oaep
     * identifier, the mask generation function must be defined by the xenc11:MGF
     * element.
     */
    @ParameterizedTest
    @CsvSource({
            "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p,,0",
            "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p,'',0",
            "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p, http://www.w3.org/2009/xmlenc11#mgf1sha1,0",
            "http://www.w3.org/2009/xmlenc11#rsa-oaep, http://www.w3.org/2009/xmlenc11#mgf1sha1,1",
            "http://www.w3.org/2009/xmlenc11#rsa-oaep, http://www.w3.org/2009/xmlenc11#mgf1sha256,1",
            "http://www.w3.org/2009/xmlenc11#rsa-oaep, http://www.w3.org/2009/xmlenc11#mgf1sha224,1",
            "http://www.w3.org/2009/xmlenc11#rsa-oaep, http://www.w3.org/2009/xmlenc11#mgf1sha384,1",
            "http://www.w3.org/2009/xmlenc11#rsa-oaep, http://www.w3.org/2009/xmlenc11#mgf1sha512,1",
    })
    void testAES128ElementRsaOaepKWCipher(String keyWrapAlgorithmURI, String mgf1URI, int mgfElementCount) throws Exception {
        // Skip test for IBM JDK
        Assumptions.assumeTrue(haveISOPadding,
                "Test testAES128ElementRsaOaepKWCipher was skipped as necessary algorithms not available!" );
        // init parameters encrypted key object
        int transportKeyBitLength = 128;

        // prepare the test document
        Document d = TestUtils.newDocument(); // source

        // Generate test recipient key pair
        KeyPairGenerator rsaKeygen = KeyPairGenerator.getInstance("RSA");
        KeyPair kp = rsaKeygen.generateKeyPair();
        PublicKey pub = kp.getPublic();

        // Generate a traffic key
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(transportKeyBitLength);
        Key ephemeralSymmetricKey = keygen.generateKey();

        XMLCipher cipherEncKey = XMLCipher.getInstance(keyWrapAlgorithmURI);
        cipherEncKey.init(XMLCipher.WRAP_MODE, pub);
        cipherEncKey.setSecureValidation(true);
        // encrypt transport key with KeyAgreement
        EncryptedKey encryptedKey =  cipherEncKey.encryptKey(d, ephemeralSymmetricKey,mgf1URI,null);
        Element enckeyDoc = cipherEncKey.martial(encryptedKey);

        NodeList mfgElements = enckeyDoc.getElementsByTagNameNS(XMLSecurityConstants.NS_XMLENC11, EncryptionConstants._TAG_MGF);
        assertEquals(mgfElementCount, mfgElements.getLength());
        assertEquals(keyWrapAlgorithmURI, encryptedKey.getEncryptionMethod().getAlgorithm());
        if (mgfElementCount > 0) {
            assertEquals(mgf1URI, encryptedKey.getEncryptionMethod().getMGFAlgorithm());
        }
    }

    /**
     * Test decryption using key agreement method processing and manual key derivation
     * where KeyAgreementMethod is present in EncryptedKey, but it is not used for decryption
     * because decryption key is provided manually. The test ensures legacy behavior is preserved
     * where some implementations implemented it own key agreement method processing
     * and XMLCipher is used just for key unwrapping.
     *
     * <p/>
     * @throws Exception Thrown when there is any problem in signing or verification
     */
    @Test
    void testDecryptionSkipKeyAgreementMethodProcessing() throws Exception {

        // init parameters encrypted key object
        String keyWrapAlgorithm = XMLCipher.AES_128_KeyWrap;
        int transportKeyBitLength = KeyUtils.getAESKeyBitSizeForWrapAlgorithm(keyWrapAlgorithm);

        // Generate test recipient key pair
        KeyPair recipientKeyPair = KeyTestUtils.generateKeyPair(KeyUtils.KeyType.SECP256R1);
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
        KeyDerivationParameters keyDerivationParameter = ConcatKDFParams
                .createBuilder(transportKeyBitLength, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256)
                .build();
        KeyAgreementParameters parameterSpec = new KeyAgreementParameters(
                KeyAgreementParameters.ActorType.ORIGINATOR,
                EncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES,
                keyDerivationParameter);

        // Generate EncryptedKey with KeyAgreementMethod
        Document doc = TestUtils.newDocument();
        EncryptedKey encryptedKey = cipherEncKey.encryptKey(doc, ephemeralSymmetricKey, parameterSpec, null);
        // assert that KeyAgreementMethod is present
        assertEquals(1, ((KeyInfoEnc) encryptedKey.getKeyInfo()).lengthAgreementMethod());

        // decrypt EncryptedKey key handled by xmlsec.
        XMLCipher kwCipherWithKeyAgreement = XMLCipher.getInstance();
        kwCipherWithKeyAgreement.init(XMLCipher.UNWRAP_MODE, privRecipientKey);
        Key symmetricKeyWithKeyAgreement = kwCipherWithKeyAgreement.decryptKey(
                encryptedKey, encryptedKey.getEncryptionMethod().getAlgorithm()
        );
        assertEquals(ephemeralSymmetricKey, symmetricKeyWithKeyAgreement);

        // decrypt EncryptedKey key manually (skip KeyAgreementMethod processing)
        // derive encrypted key manually
        KeyAgreementParameters params = XMLCipherUtil.constructRecipientKeyAgreementParameters(keyWrapAlgorithm,
                ((KeyInfoEnc) encryptedKey.getKeyInfo()).itemAgreementMethod(0), privRecipientKey);
        Key keyWrappingKey = KeyUtils.aesWrapKeyWithDHGeneratedKey(params);

        // use manually derived key to decrypt EncryptedKey
        XMLCipher kwCipherManually = XMLCipher.getInstance();
        kwCipherManually.init(XMLCipher.UNWRAP_MODE, keyWrappingKey);

        Key symmetricKeyManualDecryption = kwCipherManually.decryptKey(
                encryptedKey, encryptedKey.getEncryptionMethod().getAlgorithm()
        );
        assertEquals(ephemeralSymmetricKey, symmetricKeyManualDecryption);
    }

    /**
     * Test encryption using a generated AES 192 bit key that is
     * encrypted using a 3DES key.  Then reverse by decrypting
     * EncryptedKey by hand
     */
    @Test
    void testAES192Element3DESKWCipher() throws Exception {

        assumeFalse(isIBMJdK);

        Document d = document(); // source
        Document ed = null;
        Document dd = null;
        Element e = (Element) d.getElementsByTagName(element()).item(index());
        Element ee = null;

        String source = null;
        String target = null;

        if (haveISOPadding && haveKeyWraps) {
            source = toString(d);

            // Set up a Key Encryption Key
            byte[] bits192 = "abcdefghijklmnopqrstuvwx".getBytes();
            DESedeKeySpec keySpec = new DESedeKeySpec(bits192);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            Key kek = keyFactory.generateSecret(keySpec);

            // Generate a traffic key
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(192);
            Key key = keygen.generateKey();

            cipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES_KeyWrap);
            cipher.init(XMLCipher.WRAP_MODE, kek);
            EncryptedKey encryptedKey = cipher.encryptKey(d, key);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_192);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
            EncryptedData builder = cipher.getEncryptedData();

            KeyInfo builderKeyInfo = builder.getKeyInfo();
            if (builderKeyInfo == null) {
                builderKeyInfo = new KeyInfo(d);
                builder.setKeyInfo(builderKeyInfo);
            }

            builderKeyInfo.add(encryptedKey);

            ed = cipher.doFinal(d, e);

            //decrypt
            key = null;
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
            cipher = XMLCipher.getInstance();
            cipher.init(XMLCipher.DECRYPT_MODE, null);

            EncryptedData encryptedData = cipher.loadEncryptedData(ed, ee);

            if(encryptedData == null) {
                System.out.println("ed is null");
            }
            else if (encryptedData.getKeyInfo() == null) {
                System.out.println("ki is null");
            }
            EncryptedKey ek = encryptedData.getKeyInfo().itemEncryptedKey(0);

            if (ek != null) {
                XMLCipher keyCipher = XMLCipher.getInstance();
                keyCipher.init(XMLCipher.UNWRAP_MODE, kek);
                key = keyCipher.decryptKey(ek, encryptedData.getEncryptionMethod().getAlgorithm());
            }

            // Create a new cipher just to be paranoid
            XMLCipher cipher3 = XMLCipher.getInstance();
            cipher3.init(XMLCipher.DECRYPT_MODE, key);
            dd = cipher3.doFinal(ed, ee);

            target = toString(dd);
            assertEquals(source, target);
        } else {
            LOG.log(Level.WARNING,
                "Test testAES192Element3DESKWCipher skipped as "
                + "necessary algorithms not available"
            );
        }
    }

    @Test
    void testTripleDesElementCipher() throws Exception {
        Document d = document(); // source
        Document ed = null;      // target
        Document dd = null;      // target
        Element e = (Element) d.getElementsByTagName(element()).item(index());
        Element ee = null;

        String source = null;
        String target = null;

        if (haveISOPadding) {
            source = toString(d);

            // prepare for encryption
            byte[] passPhrase = "24 Bytes per DESede key!".getBytes();
            DESedeKeySpec keySpec = new DESedeKeySpec(passPhrase);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            SecretKey key = keyFactory.generateSecret(keySpec);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
            ed = cipher.doFinal(d, e);

            //decrypt
            cipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            cipher.init(XMLCipher.DECRYPT_MODE, key);
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
            EncryptedData encryptedData = cipher.loadEncryptedData(ed, ee);
            String algorithm = encryptedData.getEncryptionMethod().getAlgorithm();
            assertEquals(XMLCipher.TRIPLEDES, algorithm);
            dd = cipher.doFinal(ed, ee);

            target = toString(dd);
            assertEquals(source, target);
        } else {
            LOG.log(Level.WARNING,
                "Test testTripleDesElementCipher skipped as necessary algorithms not available"
            );
        }
    }

    @Test
    void testAes128ElementCipher() throws Exception {
        byte[] bits128 = {
                          (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13,
                          (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
                          (byte) 0x18, (byte) 0x19, (byte) 0x1A, (byte) 0x1B,
                          (byte) 0x1C, (byte) 0x1D, (byte) 0x1E, (byte) 0x1F};
        Key key = new SecretKeySpec(bits128, "AES");

        Document d = document(); // source
        Document ed = null;      // target
        Document dd = null;      // target
        Element e = (Element) d.getElementsByTagName(element()).item(index());
        Element ee = null;

        String source = null;
        String target = null;

        if (haveISOPadding) {
            source = toString(d);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_128);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
            ed = cipher.doFinal(d, e);

            //decrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_128);
            cipher.init(XMLCipher.DECRYPT_MODE, key);
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
            EncryptedData encryptedData = cipher.loadEncryptedData(ed, ee);
            String algorithm = encryptedData.getEncryptionMethod().getAlgorithm();
            assertEquals(XMLCipher.AES_128, algorithm);
            dd = cipher.doFinal(ed, ee);

            target = toString(dd);
            assertEquals(source, target);
        } else {
            LOG.log(Level.WARNING,
                "Test testAes128ElementCipher skipped as necessary algorithms not available"
            );
        }
    }

    @Test
    void testAes192ElementCipher() throws Exception {
        byte[] bits192 = {
                          (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B,
                          (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F,
                          (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13,
                          (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
                          (byte) 0x18, (byte) 0x19, (byte) 0x1A, (byte) 0x1B,
                          (byte) 0x1C, (byte) 0x1D, (byte) 0x1E, (byte) 0x1F};
        Key key = new SecretKeySpec(bits192, "AES");

        Document d = document(); // source
        Document ed = null;      // target
        Document dd = null;      // target
        Element e = (Element) d.getElementsByTagName(element()).item(index());
        Element ee = null;

        String source = null;
        String target = null;

        if (haveISOPadding) {
            source = toString(d);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_192);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
            ed = cipher.doFinal(d, e);

            //decrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_192);
            cipher.init(XMLCipher.DECRYPT_MODE, key);
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
            EncryptedData encryptedData = cipher.loadEncryptedData(ed, ee);
            String algorithm = encryptedData.getEncryptionMethod().getAlgorithm();
            assertEquals(XMLCipher.AES_192, algorithm);
            dd = cipher.doFinal(ed, ee);

            target = toString(dd);
            assertEquals(source, target);
        } else {
            LOG.log(Level.WARNING, "Test testAes192ElementCipher skipped as necessary algorithms not available");
        }
    }

    @Test
    void testAes265ElementCipher() throws Exception {
        byte[] bits256 = {
                          (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03,
                          (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
                          (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B,
                          (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F,
                          (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13,
                          (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
                          (byte) 0x18, (byte) 0x19, (byte) 0x1A, (byte) 0x1B,
                          (byte) 0x1C, (byte) 0x1D, (byte) 0x1E, (byte) 0x1F};
        Key key = new SecretKeySpec(bits256, "AES");

        Document d = document(); // source
        Document ed = null;      // target
        Document dd = null;      // target
        Element e = (Element) d.getElementsByTagName(element()).item(index());
        Element ee = null;

        String source = null;
        String target = null;

        if (haveISOPadding) {
            source = toString(d);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_256);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
            ed = cipher.doFinal(d, e);

            //decrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_256);
            cipher.init(XMLCipher.DECRYPT_MODE, key);
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
            EncryptedData encryptedData = cipher.loadEncryptedData(ed, ee);
            String algorithm = encryptedData.getEncryptionMethod().getAlgorithm();
            assertEquals(XMLCipher.AES_256, algorithm);
            dd = cipher.doFinal(ed, ee);

            target = toString(dd);
            assertEquals(source, target);
        } else {
            LOG.log(Level.WARNING, "Test testAes265ElementCipher skipped as necessary algorithms not available");
        }
    }

    /*
     * Test case for when the entire document is encrypted and decrypted
     * In this case the EncryptedData becomes the root element of the document
     */
    @Test
    void testTripleDesDocumentCipher() throws Exception {
        Document d = document(); // source
        Document ed = null;      // target
        Document dd = null;      // target
        Element e = d.getDocumentElement();
        Element ee = null;

        String source = null;
        String target = null;

        if (haveISOPadding) {
            source = toString(d);

            // prepare for encryption
            byte[] passPhrase = "24 Bytes per DESede key!".getBytes();
            DESedeKeySpec keySpec = new DESedeKeySpec(passPhrase);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            SecretKey key = keyFactory.generateSecret(keySpec);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
            ed = cipher.doFinal(d, e);

            //decrypt
            cipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            cipher.init(XMLCipher.DECRYPT_MODE, key);
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
            dd = cipher.doFinal(ed, ee);

            target = toString(dd);
            assertEquals(source, target);
        } else {
            LOG.log(Level.WARNING,
                "Test testTripleDesDocumentCipher skipped as "
                + "necessary algorithms not available"
            );
        }
    }

    @Test
    void testEncryptionProperties() throws Exception {
        Document d = document(); // source
        Document ed = null;      // target
        Document dd = null;      // target
        Element e = d.getDocumentElement();
        Element ee = null;

        String source = null;
        String target = null;

        if (haveISOPadding) {
            source = toString(d);

            // prepare for encryption
            byte[] passPhrase = "24 Bytes per DESede key!".getBytes();
            DESedeKeySpec keySpec = new DESedeKeySpec(passPhrase);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            SecretKey key = keyFactory.generateSecret(keySpec);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);

            // Add EncryptionProperties
            Element elem = d.createElement("CustomInformation");
            elem.setTextContent("Some text content");

            EncryptionProperties eps = cipher.createEncryptionProperties();
            EncryptionProperty ep = cipher.createEncryptionProperty();
            ep.addEncryptionInformation(elem);
            ep.setId("_124124");
            ep.setTarget("http://localhost/");
            ep.setAttribute("xml:lang", "en");
            eps.addEncryptionProperty(ep);

            EncryptedData encData = cipher.getEncryptedData();
            encData.setEncryptionProperties(eps);

            ed = cipher.doFinal(d, e);
            // XMLUtils.outputDOM(ed, System.out);

            //decrypt
            cipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            cipher.init(XMLCipher.DECRYPT_MODE, key);
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
            dd = cipher.doFinal(ed, ee);

            target = toString(dd);
            assertEquals(source, target);
        } else {
            LOG.log(Level.WARNING,
                "Test testTripleDesDocumentCipher skipped as "
                + "necessary algorithms not available"
            );
        }
    }

    /*
     * Test a Cipher Reference
     */
    @Test
    void testSameDocumentCipherReference() throws Exception {

        if (haveISOPadding) {
            Document d = TestUtils.newDocument();

            Element docElement = d.createElement("EncryptedDoc");
            d.appendChild(docElement);

            // Create the XMLCipher object
            cipher = XMLCipher.getInstance();

            EncryptedData ed =
                cipher.createEncryptedData(CipherData.REFERENCE_TYPE,
                                           "#CipherTextId");
            EncryptionMethod em =
                cipher.createEncryptionMethod(XMLCipher.AES_128);

            ed.setEncryptionMethod(em);

            org.apache.xml.security.encryption.Transforms xencTransforms =
                cipher.createTransforms(d);
            ed.getCipherData().getCipherReference().setTransforms(xencTransforms);
            org.apache.xml.security.transforms.Transforms dsTransforms =
                xencTransforms.getDSTransforms();

            // An XPath transform
            XPathContainer xpc = new XPathContainer(d);
            xpc.setXPath("self::text()[parent::CipherText[@Id=\"CipherTextId\"]]");
            dsTransforms.addTransform(
                org.apache.xml.security.transforms.Transforms.TRANSFORM_XPATH,
                xpc.getElementPlusReturns()
            );

            // Add a Base64 Transforms
            dsTransforms.addTransform(
                org.apache.xml.security.transforms.Transforms.TRANSFORM_BASE64_DECODE
            );

            Element ee = cipher.martial(d, ed);

            docElement.appendChild(ee);

            // Add the cipher text
            Element encryptedElement = d.createElement("CipherText");
            encryptedElement.setAttributeNS(null, "Id", "CipherTextId");
            encryptedElement.setIdAttributeNS(null, "Id", true);
            encryptedElement.appendChild(d.createTextNode(tstBase64EncodedString));
            docElement.appendChild(encryptedElement);
            // dump(d);

            // Now the decrypt, with a brand new cipher
            XMLCipher cipherDecrypt = XMLCipher.getInstance();
            Key key = new SecretKeySpec("abcdefghijklmnop".getBytes(StandardCharsets.US_ASCII), "AES");

            cipherDecrypt.init(XMLCipher.DECRYPT_MODE, key);
            byte[] decryptBytes = cipherDecrypt.decryptToByteArray(ee);

            assertEquals("A test encrypted secret",
                        new String(decryptBytes, StandardCharsets.US_ASCII));
        } else {
            LOG.log(Level.WARNING,
                "Test testSameDocumentCipherReference skipped as "
                + "necessary algorithms not available"
            );
        }
    }

    /*
     * Test physical representation of decrypted element, see SANTUARIO-309
     */
    @Test
    void testPhysicalRepresentation() throws Exception {

        if (haveISOPadding) {
            byte[] bits192 = "abcdefghijklmnopqrstuvwx".getBytes();
            DESedeKeySpec keySpec = new DESedeKeySpec(bits192);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            SecretKey secretKey = keyFactory.generateSecret(keySpec);

            // Test inherited namespaces don't add extra attributes
            // Test unused namespaces are preserved
            final String DATA1 = "<ns:root xmlns:ns=\"ns.com\"><ns:elem xmlns:ns2=\"ns2.com\">11</ns:elem></ns:root>";
            Document doc = null;
            try (InputStream is = new ByteArrayInputStream(DATA1.getBytes(StandardCharsets.UTF_8))) {
                doc = XMLUtils.read(is, false);
            }
            Element elem = (Element)doc.getDocumentElement().getFirstChild();

            XMLCipher dataCipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            dataCipher.init(XMLCipher.ENCRYPT_MODE, secretKey);
            dataCipher.doFinal(doc, elem);

            Element encrElem = (Element)doc.getDocumentElement().getFirstChild();
            assertEquals("EncryptedData", encrElem.getLocalName());

            XMLCipher deCipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            deCipher.init(XMLCipher.DECRYPT_MODE, secretKey);
            deCipher.doFinal(doc, encrElem);

            Element decrElem = (Element)doc.getDocumentElement().getFirstChild();
            assertEquals("ns:elem", decrElem.getNodeName());
            assertEquals("ns.com", decrElem.getNamespaceURI());
            assertEquals(1, decrElem.getAttributes().getLength());
            Attr attr = (Attr)decrElem.getAttributes().item(0);
            assertEquals("xmlns:ns2", attr.getName());
            assertEquals("ns2.com", attr.getValue());

            // Test default namespace undeclaration is preserved
            final String DATA2 = "<ns:root xmlns=\"defns.com\" xmlns:ns=\"ns.com\"><elem xmlns=\"\">11</elem></ns:root>";
            try (InputStream is = new ByteArrayInputStream(DATA2.getBytes(StandardCharsets.UTF_8))) {
                doc = XMLUtils.read(is, false);
            }
            elem = (Element)doc.getDocumentElement().getFirstChild();

            dataCipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            dataCipher.init(XMLCipher.ENCRYPT_MODE, secretKey);
            dataCipher.doFinal(doc, elem);

            encrElem = (Element)doc.getDocumentElement().getFirstChild();
            assertEquals("EncryptedData", encrElem.getLocalName());

            deCipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            deCipher.init(XMLCipher.DECRYPT_MODE, secretKey);
            deCipher.doFinal(doc, encrElem);

            decrElem = (Element)doc.getDocumentElement().getFirstChild();
            assertEquals("elem", decrElem.getNodeName());
            assertNull(decrElem.getNamespaceURI());
            assertEquals(1, decrElem.getAttributes().getLength());
            attr = (Attr)decrElem.getAttributes().item(0);
            assertEquals("xmlns", attr.getName());
            assertEquals("", attr.getValue());

            // Test comments and PIs are not treated specially when serializing element content.
            // Other c14n algorithms add a newline after comments and PIs, when they are before or after the document element.
            final String DATA3 = "<root><!--comment1--><?pi1 target1?><elem/><!--comment2--><?pi2 target2?></root>";
            try (InputStream is = new ByteArrayInputStream(DATA3.getBytes(StandardCharsets.UTF_8))) {
                doc = XMLUtils.read(is, false);
            }
            elem = doc.getDocumentElement();

            dataCipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            dataCipher.init(XMLCipher.ENCRYPT_MODE, secretKey);
            dataCipher.doFinal(doc, elem, true);

            encrElem = (Element)elem.getFirstChild();
            assertEquals("EncryptedData", encrElem.getLocalName());
            assertNull(encrElem.getNextSibling());

            deCipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            deCipher.init(XMLCipher.DECRYPT_MODE, secretKey);
            deCipher.doFinal(doc, encrElem);

            Node n = elem.getFirstChild();
            assertEquals(Node.COMMENT_NODE, n.getNodeType());
            n = n.getNextSibling();
            assertEquals(Node.PROCESSING_INSTRUCTION_NODE, n.getNodeType());
            n = n.getNextSibling();
            assertEquals(Node.ELEMENT_NODE, n.getNodeType());
            n = n.getNextSibling();
            assertEquals(Node.COMMENT_NODE, n.getNodeType());
            n = n.getNextSibling();
            assertEquals(Node.PROCESSING_INSTRUCTION_NODE, n.getNodeType());
            n = n.getNextSibling();
            assertNull(n);
        } else {
            LOG.log(Level.WARNING,
                "Test testPhysicalRepresentation skipped as "
                + "necessary algorithms not available"
            );
        }
    }

    @Test
    void testSerializedData() throws Exception {
        if (!haveISOPadding) {
            LOG.log(Level.WARNING, "Test testSerializedData skipped as necessary algorithms not available");
            return;
        }

        byte[] bits128 = {
                          (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13,
                          (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
                          (byte) 0x18, (byte) 0x19, (byte) 0x1A, (byte) 0x1B,
                          (byte) 0x1C, (byte) 0x1D, (byte) 0x1E, (byte) 0x1F};
        Key key = new SecretKeySpec(bits128, "AES");

        Document d = document(); // source
        Element e = (Element) d.getElementsByTagName(element()).item(index());

        // encrypt
        cipher = XMLCipher.getInstance(XMLCipher.AES_128);
        cipher.init(XMLCipher.ENCRYPT_MODE, key);

        // serialize element ...
        Canonicalizer canon =
            Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        canon.canonicalizeSubtree(e, baos);
        baos.close();
        String before = baos.toString(StandardCharsets.UTF_8);

        byte[] serialized = baos.toByteArray();
        EncryptedData encryptedData = null;
        try (InputStream is = new ByteArrayInputStream(serialized)) {
            encryptedData = cipher.encryptData(d, EncryptionConstants.TYPE_ELEMENT, is);
        }

        //decrypt
        XMLCipher dcipher = XMLCipher.getInstance(XMLCipher.AES_128);
        dcipher.init(XMLCipher.DECRYPT_MODE, key);
        String algorithm = encryptedData.getEncryptionMethod().getAlgorithm();
        assertEquals(XMLCipher.AES_128, algorithm);
        byte[] bytes = dcipher.decryptToByteArray(dcipher.martial(encryptedData));
        String after = new String(bytes, StandardCharsets.UTF_8);
        assertEquals(before, after);

        // test with null type
        try (InputStream is = new ByteArrayInputStream(serialized)) {
            encryptedData = cipher.encryptData(d, null, is);
        }
    }

    @Test
    void testEncryptedKeyWithRecipient() throws Exception {
        String filename =
            "src/test/resources/org/apache/xml/security/encryption/encryptedKey.xml";
        if (basedir != null && basedir.length() != 0) {
            filename = basedir + "/" + filename;
        }
        Document document = XMLUtils.read(new File(filename), false);

        XMLCipher keyCipher = XMLCipher.getInstance();
        keyCipher.init(XMLCipher.UNWRAP_MODE, null);

        NodeList ekList =
            document.getElementsByTagNameNS(
                EncryptionConstants.EncryptionSpecNS, EncryptionConstants._TAG_ENCRYPTEDKEY
            );
        for (int i = 0; i < ekList.getLength(); i++) {
            EncryptedKey ek =
                keyCipher.loadEncryptedKey(document, (Element) ekList.item(i));
            assertNotNull(ek.getRecipient());
        }
    }

    @Test
    void testEecryptToByteArray() throws Exception {
        Assumptions.assumeTrue(bcInstalled);

        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        Key key = keygen.generateKey();

        Document document = document();

        XMLCipher cipher = XMLCipher.getInstance(XMLCipher.AES_128_GCM);
        cipher.init(XMLCipher.ENCRYPT_MODE, key);
        cipher.getEncryptedData();

        Document encrypted = cipher.doFinal(document, document);

        XMLCipher xmlCipher = XMLCipher.getInstance();
        xmlCipher.init(XMLCipher.DECRYPT_MODE, key);
        Element encryptedData = (Element) encrypted.getElementsByTagNameNS(EncryptionConstants.EncryptionSpecNS, EncryptionConstants._TAG_ENCRYPTEDDATA).item(0);

        xmlCipher.decryptToByteArray(encryptedData);
    }

    @Test
    void testEncryptForDataExceeding8192bytes() throws Exception {
        boolean bcAtFirstPosition = false;
        if (Security.getProvider("BC") == null) {
            // Use reflection to add new BouncyCastleProvider
            try {
                Class<?> bouncyCastleProviderClass = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
                Provider bouncyCastleProvider = (Provider)bouncyCastleProviderClass.getConstructor().newInstance();
                Security.insertProviderAt(bouncyCastleProvider, 1);
                bcAtFirstPosition = true;
            } catch (ReflectiveOperationException e) {
                // BouncyCastle not installed, ignore
            }
        }
        Assumptions.assumeTrue(bcAtFirstPosition);

        KeyGenerator generator = KeyGenerator.getInstance("AES", "BC");
        generator.init(128);
        SecretKey key = generator.generateKey();

        XMLCipher cipher = XMLCipher.getInstance(XMLCipher.AES_128_GCM);
        cipher.init(XMLCipher.ENCRYPT_MODE, key);

        Document document = document();
        byte[] dataToEncrypt = new byte[8193];
        for (int i = 0; i < 8193; i++) {
            dataToEncrypt[i] = (byte) i;
        }
        EncryptedData encryptedData = cipher.encryptData(document, null, new ByteArrayInputStream(dataToEncrypt));

        XMLCipher decipher = XMLCipher.getInstance(XMLCipher.AES_128);
        decipher.init(XMLCipher.DECRYPT_MODE, key);
        String algorithm = encryptedData.getEncryptionMethod().getAlgorithm();
        assertEquals(XMLCipher.AES_128_GCM, algorithm);
        byte[] decryptedByteArray = decipher.decryptToByteArray(decipher.martial(encryptedData));
        assertArrayEquals(dataToEncrypt, decryptedByteArray);

        Security.removeProvider("BC");
    }

    @Test
    void testMultipleKEKs() throws Exception {

        Document d = document(); // source
        Document ed = null;
        Document dd = null;
        Element e = (Element) d.getElementsByTagName(element()).item(index());
        Element ee = null;

        String source = null;
        String target = null;

        if (haveISOPadding && haveKeyWraps) {
            source = toString(d);

            // Set up Key Encryption Key no. 1
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(192);
            Key kek1 = keygen.generateKey();

            // Set up Key Encryption Key no. 2
            Key kek2 = keygen.generateKey();

            // Generate a traffic key
            keygen = KeyGenerator.getInstance("AES");
            keygen.init(128);
            Key key = keygen.generateKey();

            cipher = XMLCipher.getInstance(XMLCipher.AES_192_KeyWrap);
            cipher.init(XMLCipher.WRAP_MODE, kek1);
            EncryptedKey encryptedKey1 = cipher.encryptKey(d, key);

            cipher.init(XMLCipher.WRAP_MODE, kek2);
            EncryptedKey encryptedKey2 = cipher.encryptKey(d, key);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_128);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
            EncryptedData builder = cipher.getEncryptedData();

            KeyInfo builderKeyInfo = builder.getKeyInfo();
            if (builderKeyInfo == null) {
                builderKeyInfo = new KeyInfo(d);
                builder.setKeyInfo(builderKeyInfo);
            }

            builderKeyInfo.add(encryptedKey1);
            builderKeyInfo.add(encryptedKey2);

            ed = cipher.doFinal(d, e);

            //decrypt
            key = null;
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
            cipher = XMLCipher.getInstance(XMLCipher.AES_128);
            cipher.init(XMLCipher.DECRYPT_MODE, null);
            cipher.setKEK(kek2);
            dd = cipher.doFinal(ed, ee);

            target = toString(dd);
            assertEquals(source, target);
        } else {
            LOG.log(Level.WARNING,
                "Test testAES128ElementAES192KWCipherUsingKEK skipped as "
                + "necessary algorithms not available"
            );
        }
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
        try (FileInputStream inputStream = new FileInputStream(f)) {
            return XMLUtils.read(inputStream, false);
        }
    }

    private String element() {
        return elementName;
    }

    private int index() {
        return Integer.parseInt(elementIndex);
    }

}
