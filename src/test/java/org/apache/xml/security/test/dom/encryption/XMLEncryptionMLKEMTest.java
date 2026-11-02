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

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.encryption.params.HKDFParams;
import org.apache.xml.security.encryption.params.KeyEncapsulationParameters;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.utils.KeyUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for ML-KEM (FIPS 203) XML encryption via the DOM XMLCipher API, using the W3C
 * "XML Security: Generic Hybrid Cipher" key transport structure
 * (https://www.w3.org/TR/xmlsec-generic-hybrid/): the recipient's ML-KEM public key
 * encapsulates a shared secret (via {@code javax.crypto.KEM}), a key-wrap key is derived
 * from it with HKDF, and the content-encryption key (CEK) is AES-KeyWrap'd with that
 * derived key. {@code xenc:CipherValue} holds the concatenation of the KEM encapsulation
 * and the wrapped CEK; the KEM algorithm, key derivation method and data-encapsulation
 * (AES-KeyWrap) algorithm are all explicit, named elements under
 * {@code ghc:GenericHybridCipherMethod} rather than an opaque blob (see SANTUARIO-633).
 *
 * <p>Key pairs are generated on the fly in {@code @BeforeAll}; no pre-generated
 * key material is committed to the repository.
 *
 * <p>Run with the Maven {@code bouncycastle} profile on Java 21+ (the {@code javax.crypto.KEM}
 * API, JEP 452, is used internally via reflection - see {@link KeyUtils#kemEncapsulate}):
 * <pre>mvn test -Dtest=XMLEncryptionMLKEMTest -P bouncycastle</pre>
 */
class XMLEncryptionMLKEMTest {

    private static boolean mlKemAvailable;
    private static boolean bcAddedForTheTest;

    /** Namespace of the HKDFParams / Salt / Info elements (xmldsig-more, 2021). */
    private static final String XMLDSIG_MORE_NS = "http://www.w3.org/2021/04/xmldsig-more#";

    private static java.util.Map<String, KeyPair> keyPairs = new java.util.HashMap<>();

    @BeforeAll
    static void setUp() {
        org.apache.xml.security.Init.init();

        if (Security.getProvider("BC") == null) {
            try {
                Class<?> cls = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
                Provider bc = (Provider) cls.getConstructor().newInstance();
                Security.addProvider(bc);
                bcAddedForTheTest = true;
            } catch (ReflectiveOperationException e) {
                mlKemAvailable = false;
                return;
            }
        }

        try {
            for (String alg : new String[]{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}) {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, "BC");
                keyPairs.put(alg, kpg.generateKeyPair());
            }
            // javax.crypto.KEM (JEP 452) is only available since Java 21; the KemEncapsulation
            // helper is used via reflection, so probe it here rather than failing deep inside
            // encryptKey.
            Class.forName("javax.crypto.KEM");
            mlKemAvailable = true;
        } catch (Exception | LinkageError e) {
            mlKemAvailable = false;
        }
    }

    @AfterAll
    static void tearDown() {
        if (bcAddedForTheTest) {
            Security.removeProvider("BC");
        }
    }

    @ParameterizedTest
    @CsvSource({
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_512  + ",ML-KEM-512",
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_768  + ",ML-KEM-768",
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_1024 + ",ML-KEM-1024",
    })
    void testMLKEMEncryptDecrypt(String keyEncapsulationUri, String jcaAlgorithm) throws Exception {
        Assumptions.assumeTrue(mlKemAvailable, "ML-KEM requires BouncyCastle 1.84+ and Java 21+ (javax.crypto.KEM)");

        PublicKey  pubKey  = keyPairs.get(jcaAlgorithm).getPublic();
        PrivateKey privKey = keyPairs.get(jcaAlgorithm).getPrivate();

        // Build a minimal XML document to encrypt
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().newDocument();
        Element root = doc.createElement("PaymentInfo");
        root.setTextContent("CardNumber:4019111111111111");
        doc.appendChild(root);

        // Generate a random AES-256 content-encryption key (CEK)
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey cek = kg.generateKey();

        // --- ENCRYPT ---
        // Encapsulate a shared secret to the recipient's ML-KEM public key, derive an
        // AES-256 key-wrap key from it via HKDF-SHA256, and wrap the CEK with that key.
        String kwAlgorithm = EncryptionConstants.ALGO_ID_KEYWRAP_AES256;
        int wrapKeyBitLength = KeyUtils.getAESKeyBitSizeForWrapAlgorithm(kwAlgorithm);
        HKDFParams kdfParams = HKDFParams.createBuilder(wrapKeyBitLength, XMLSignature.ALGO_ID_MAC_HMAC_SHA256).build();
        AlgorithmParameterSpec keyEncapsulationParameters =
                new KeyEncapsulationParameters(keyEncapsulationUri, kdfParams);

        XMLCipher keyCipher = XMLCipher.getInstance(kwAlgorithm);
        keyCipher.init(XMLCipher.WRAP_MODE, pubKey);
        EncryptedKey encryptedKey = keyCipher.encryptKey(doc, cek, keyEncapsulationParameters, null);

        // Verify the produced EncryptedKey uses the Generic Hybrid Cipher structure, not an
        // opaque flat key-transport blob
        assertEquals(EncryptionConstants.ALGO_ID_KEYTRANSPORT_GENERIC_HYBRID,
                encryptedKey.getEncryptionMethod().getAlgorithm());
        assertEquals(keyEncapsulationUri, encryptedKey.getEncryptionMethod().getKeyEncapsulationAlgorithm());
        assertEquals(kwAlgorithm, encryptedKey.getEncryptionMethod().getDataEncapsulationAlgorithm());
        assertTrue(encryptedKey.getEncryptionMethod().getKeyEncapsulationKeyLength() > 0);

        // Encrypt the document content with AES-256-GCM
        XMLCipher dataCipher = XMLCipher.getInstance(XMLCipher.AES_256_GCM);
        dataCipher.init(XMLCipher.ENCRYPT_MODE, cek);
        EncryptedData encryptedData = dataCipher.getEncryptedData();

        KeyInfo keyInfo = new KeyInfo(doc);
        keyInfo.add(encryptedKey);
        encryptedData.setKeyInfo(keyInfo);

        doc = dataCipher.doFinal(doc, root, false);

        // Serialise to bytes to simulate wire transfer
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        javax.xml.transform.Transformer t =
                javax.xml.transform.TransformerFactory.newInstance().newTransformer();
        t.transform(new javax.xml.transform.dom.DOMSource(doc),
                    new javax.xml.transform.stream.StreamResult(bos));

        // Verify the serialised XML carries the spec's element names, per
        // https://www.w3.org/TR/xmlsec-generic-hybrid/ section 6.1 "Key Transport Example"
        String serialized = bos.toString(java.nio.charset.StandardCharsets.UTF_8);
        assertTrue(serialized.contains("GenericHybridCipherMethod"), "Missing GenericHybridCipherMethod element");
        assertTrue(serialized.contains("KeyEncapsulationMethod"), "Missing KeyEncapsulationMethod element");
        assertTrue(serialized.contains("DataEncapsulationMethod"), "Missing DataEncapsulationMethod element");
        assertTrue(serialized.contains("http://www.w3.org/2010/xmlsec-ghc#generic-hybrid"),
                "Missing Generic Hybrid Cipher EncryptionMethod algorithm");

        // --- DECRYPT ---
        Document encDoc = dbf.newDocumentBuilder()
                .parse(new java.io.ByteArrayInputStream(bos.toByteArray()));

        Element encDataElem = (Element) encDoc.getElementsByTagNameNS(
                EncryptionConstants.EncryptionSpecNS, "EncryptedData").item(0);

        XMLCipher decryptCipher = XMLCipher.getInstance();
        decryptCipher.init(XMLCipher.DECRYPT_MODE, null);
        EncryptedData encData = decryptCipher.loadEncryptedData(encDoc, encDataElem);

        // Unwrap the CEK using the recipient's ML-KEM private key
        EncryptedKey ek = encData.getKeyInfo().itemEncryptedKey(0);
        XMLCipher unwrapCipher = XMLCipher.getInstance();
        unwrapCipher.init(XMLCipher.UNWRAP_MODE, privKey);
        Key recoveredCek = unwrapCipher.decryptKey(
                ek, encData.getEncryptionMethod().getAlgorithm());

        // Decrypt document content
        decryptCipher.init(XMLCipher.DECRYPT_MODE, recoveredCek);
        Document decryptedDoc = decryptCipher.doFinal(encDoc, encDataElem);

        Element decryptedRoot = decryptedDoc.getDocumentElement();
        assertEquals("PaymentInfo", decryptedRoot.getLocalName());
        assertEquals("CardNumber:4019111111111111", decryptedRoot.getTextContent());
    }

    @ParameterizedTest
    @CsvSource({
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_512  + ",ML-KEM-512",
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_768  + ",ML-KEM-768",
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_1024 + ",ML-KEM-1024",
    })
    void testMLKEMWrongRecipientPrivateKeyFailsCleanly(String keyEncapsulationUri, String jcaAlgorithm)
            throws Exception {
        Assumptions.assumeTrue(mlKemAvailable, "ML-KEM requires BouncyCastle 1.84+ and Java 21+ (javax.crypto.KEM)");

        PublicKey recipientAPub = keyPairs.get(jcaAlgorithm).getPublic();
        byte[] encryptedXml = encryptToRecipient(recipientAPub, keyEncapsulationUri);

        // A second, independent recipient - not the one the message was encrypted to.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(jcaAlgorithm, "BC");
        PrivateKey wrongPrivateKey = kpg.generateKeyPair().getPrivate();

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document encDoc = dbf.newDocumentBuilder().parse(new java.io.ByteArrayInputStream(encryptedXml));
        Element encDataElem = (Element) encDoc.getElementsByTagNameNS(
                EncryptionConstants.EncryptionSpecNS, "EncryptedData").item(0);

        XMLCipher decryptCipher = XMLCipher.getInstance();
        decryptCipher.init(XMLCipher.DECRYPT_MODE, null);
        EncryptedData encData = decryptCipher.loadEncryptedData(encDoc, encDataElem);
        EncryptedKey ek = encData.getKeyInfo().itemEncryptedKey(0);

        XMLCipher unwrapCipher = XMLCipher.getInstance();
        unwrapCipher.init(XMLCipher.UNWRAP_MODE, wrongPrivateKey);

        // Decapsulating with the wrong private key yields a different shared secret (ML-KEM's
        // implicit-rejection design does not signal failure at that layer), so the derived
        // AES key-wrap key is wrong; the AES-KeyWrap integrity check then fails. The important
        // property under test is that this throws rather than silently handing back a Key
        // built from the wrong shared secret - decryptKey() must never return in this case.
        assertThrows(XMLEncryptionException.class,
                () -> unwrapCipher.decryptKey(ek, encData.getEncryptionMethod().getAlgorithm()));
    }

    @ParameterizedTest
    @CsvSource({
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_512  + ",ML-KEM-512",
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_768  + ",ML-KEM-768",
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_1024 + ",ML-KEM-1024",
    })
    void testMLKEMTruncatedEncapsulationRejected(String keyEncapsulationUri, String jcaAlgorithm) throws Exception {
        Assumptions.assumeTrue(mlKemAvailable, "ML-KEM requires BouncyCastle 1.84+ and Java 21+ (javax.crypto.KEM)");

        PrivateKey privKey = keyPairs.get(jcaAlgorithm).getPrivate();
        PublicKey pubKey = keyPairs.get(jcaAlgorithm).getPublic();
        byte[] encryptedXml = encryptToRecipient(pubKey, keyEncapsulationUri);

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document encDoc = dbf.newDocumentBuilder().parse(new java.io.ByteArrayInputStream(encryptedXml));

        // Truncate the EncryptedKey's CipherValue (the concatenation of the KEM encapsulation C0
        // and the AES-wrapped CEK C1) to well under half its length - shorter than any ML-KEM
        // variant's encapsulationSize() - *before* it is ever parsed into an EncryptedKey object,
        // so the corruption is guaranteed to be observed on the decrypt path.
        Element encryptedKeyElem = (Element) encDoc.getElementsByTagNameNS(
                EncryptionConstants.EncryptionSpecNS, "EncryptedKey").item(0);
        Element cipherValueElem = (Element) encryptedKeyElem.getElementsByTagNameNS(
                EncryptionConstants.EncryptionSpecNS, "CipherValue").item(0);
        byte[] combined = Base64.getMimeDecoder().decode(cipherValueElem.getTextContent());
        byte[] truncated = java.util.Arrays.copyOf(combined, combined.length / 2);
        replaceTextContent(encDoc, cipherValueElem, Base64.getEncoder().encodeToString(truncated));

        Element encDataElem = (Element) encDoc.getElementsByTagNameNS(
                EncryptionConstants.EncryptionSpecNS, "EncryptedData").item(0);
        XMLCipher decryptCipher = XMLCipher.getInstance();
        decryptCipher.init(XMLCipher.DECRYPT_MODE, null);
        EncryptedData encData = decryptCipher.loadEncryptedData(encDoc, encDataElem);
        EncryptedKey ek = encData.getKeyInfo().itemEncryptedKey(0);

        XMLCipher unwrapCipher = XMLCipher.getInstance();
        unwrapCipher.init(XMLCipher.UNWRAP_MODE, privKey);

        // KeyUtils.kemDecapsulate() explicitly checks the ciphertext length against
        // encapsulationSize() and throws XMLEncryptionException("KeyDerivation.MissingParameters")
        // rather than reading past the end of the array.
        assertThrows(XMLEncryptionException.class,
                () -> unwrapCipher.decryptKey(ek, encData.getEncryptionMethod().getAlgorithm()));
    }

    /**
     * Runs the encrypt half of the round trip for the given key encapsulation algorithm (same
     * structure as {@link #testMLKEMEncryptDecrypt}) and returns the serialised encrypted XML,
     * for tests that want to corrupt or otherwise interfere with the decrypt half.
     */
    private byte[] encryptToRecipient(PublicKey pubKey, String keyEncapsulationUri) throws Exception {
        int wrapKeyBitLength = KeyUtils.getAESKeyBitSizeForWrapAlgorithm(EncryptionConstants.ALGO_ID_KEYWRAP_AES256);
        HKDFParams kdfParams = HKDFParams.createBuilder(wrapKeyBitLength, XMLSignature.ALGO_ID_MAC_HMAC_SHA256).build();
        return encryptToRecipient(pubKey, keyEncapsulationUri, kdfParams);
    }

    private byte[] encryptToRecipient(PublicKey pubKey, String keyEncapsulationUri, HKDFParams kdfParams)
            throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().newDocument();
        Element root = doc.createElement("PaymentInfo");
        root.setTextContent("CardNumber:4019111111111111");
        doc.appendChild(root);

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey cek = kg.generateKey();

        String kwAlgorithm = EncryptionConstants.ALGO_ID_KEYWRAP_AES256;
        AlgorithmParameterSpec keyEncapsulationParameters =
                new KeyEncapsulationParameters(keyEncapsulationUri, kdfParams);

        XMLCipher keyCipher = XMLCipher.getInstance(kwAlgorithm);
        keyCipher.init(XMLCipher.WRAP_MODE, pubKey);
        EncryptedKey encryptedKey = keyCipher.encryptKey(doc, cek, keyEncapsulationParameters, null);

        XMLCipher dataCipher = XMLCipher.getInstance(XMLCipher.AES_256_GCM);
        dataCipher.init(XMLCipher.ENCRYPT_MODE, cek);
        EncryptedData encryptedData = dataCipher.getEncryptedData();

        KeyInfo keyInfo = new KeyInfo(doc);
        keyInfo.add(encryptedKey);
        encryptedData.setKeyInfo(keyInfo);

        doc = dataCipher.doFinal(doc, root, false);

        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        javax.xml.transform.Transformer t =
                javax.xml.transform.TransformerFactory.newInstance().newTransformer();
        t.transform(new javax.xml.transform.dom.DOMSource(doc),
                    new javax.xml.transform.stream.StreamResult(bos));
        return bos.toByteArray();
    }


    /**
     * Malformed key-transport metadata in the EncryptedKey must be rejected as
     * {@link XMLEncryptionException}, the decrypt API's declared failure type, rather than
     * escaping as a NumberFormatException (non-numeric or empty {@code ghc:KeyLen}) or an
     * IllegalArgumentException (malformed base64 in the HKDF {@code Salt} or {@code Info}).
     * All of these values are parsed from the untrusted message before any private-key operation.
     */
    @ParameterizedTest
    @CsvSource({
        EncryptionConstants.EncryptionSpecGHCNS + ",KeyLen,notanumber",
        EncryptionConstants.EncryptionSpecGHCNS + ",KeyLen,''",
        XMLDSIG_MORE_NS + ",Salt,!!!not-base64!!!",
        XMLDSIG_MORE_NS + ",Info,@@@@"
    })
    void testMLKEMMalformedKeyTransportMetadataRejected(String namespace, String localName, String badText)
            throws Exception {
        Assumptions.assumeTrue(mlKemAvailable, "ML-KEM requires BouncyCastle 1.84+ and Java 21+ (javax.crypto.KEM)");

        KeyPair kp = keyPairs.get("ML-KEM-768");
        Document encDoc = parse(encryptToRecipientWithHkdfSaltAndInfo(kp.getPublic()));
        Element target = (Element) encDoc.getElementsByTagNameNS(namespace, localName).item(0);
        assertNotNull(target, "expected a <" + localName + "> element to mutate");
        replaceTextContent(encDoc, target, badText);

        assertThrows(XMLEncryptionException.class, () -> decryptDocument(encDoc, kp.getPrivate()));
    }

    /**
     * A childless {@code <ghc:KeyLen/>} has no text node at all; reading it must not surface as
     * a NullPointerException from the decrypt path.
     */
    @Test
    void testMLKEMChildlessKeyLenRejected() throws Exception {
        Assumptions.assumeTrue(mlKemAvailable, "ML-KEM requires BouncyCastle 1.84+ and Java 21+ (javax.crypto.KEM)");

        KeyPair kp = keyPairs.get("ML-KEM-768");
        Document encDoc = parse(encryptToRecipient(kp.getPublic(), EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_768));
        Element keyLen = (Element) encDoc.getElementsByTagNameNS(
                EncryptionConstants.EncryptionSpecGHCNS, "KeyLen").item(0);
        assertNotNull(keyLen, "expected a <KeyLen> element to mutate");
        while (keyLen.hasChildNodes()) {
            keyLen.removeChild(keyLen.getFirstChild());
        }

        assertThrows(XMLEncryptionException.class, () -> decryptDocument(encDoc, kp.getPrivate()));
    }

    /** Encrypts with an HKDF that carries explicit Salt and Info elements, so they exist to mutate. */
    private byte[] encryptToRecipientWithHkdfSaltAndInfo(PublicKey pubKey) throws Exception {
        int wrapKeyBitLength = KeyUtils.getAESKeyBitSizeForWrapAlgorithm(EncryptionConstants.ALGO_ID_KEYWRAP_AES256);
        HKDFParams kdfParams = HKDFParams.createBuilder(wrapKeyBitLength, XMLSignature.ALGO_ID_MAC_HMAC_SHA256)
                .salt(new byte[]{1, 2, 3, 4, 5, 6, 7, 8})
                .info(new byte[]{9, 10, 11, 12})
                .build();
        return encryptToRecipient(pubKey, EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_768, kdfParams);
    }

    private Document parse(byte[] xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder().parse(new java.io.ByteArrayInputStream(xml));
    }

    /** The full decrypt path: load the EncryptedData, unwrap the CEK with the ML-KEM private key, decrypt. */
    private void decryptDocument(Document encDoc, PrivateKey privKey) throws Exception {
        Element encDataElem = (Element) encDoc.getElementsByTagNameNS(
                EncryptionConstants.EncryptionSpecNS, "EncryptedData").item(0);
        XMLCipher decryptCipher = XMLCipher.getInstance();
        decryptCipher.init(XMLCipher.DECRYPT_MODE, null);
        EncryptedData encData = decryptCipher.loadEncryptedData(encDoc, encDataElem);
        EncryptedKey ek = encData.getKeyInfo().itemEncryptedKey(0);
        XMLCipher unwrapCipher = XMLCipher.getInstance();
        unwrapCipher.init(XMLCipher.UNWRAP_MODE, privKey);
        Key cek = unwrapCipher.decryptKey(ek, encData.getEncryptionMethod().getAlgorithm());
        decryptCipher.init(XMLCipher.DECRYPT_MODE, cek);
        decryptCipher.doFinal(encDoc, encDataElem);
    }

    private void replaceTextContent(Document doc, Element element, String newText) {
        NodeList children = element.getChildNodes();
        for (int i = children.getLength() - 1; i >= 0; i--) {
            element.removeChild(children.item(i));
        }
        Text textNode = doc.createTextNode(newText);
        element.appendChild(textNode);
    }
}
