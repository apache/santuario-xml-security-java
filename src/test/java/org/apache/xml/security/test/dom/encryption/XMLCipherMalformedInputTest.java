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
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.encryption.params.HKDFParams;
import org.apache.xml.security.encryption.params.KeyAgreementParameters;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.utils.KeyUtils;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Malformed values in (untrusted) EncryptedData / EncryptedKey structures must be reported as
 * {@link XMLEncryptionException}, the exception type declared by the XMLCipher decrypt API, rather
 * than escaping as an unchecked IllegalArgumentException, NumberFormatException or
 * NullPointerException.
 */
class XMLCipherMalformedInputTest {

    private static final String XENC = EncryptionConstants.EncryptionSpecNS;
    /** Rejected by the MIME base64 decoder ("Last unit does not have enough valid bits"). */
    private static final String BAD_BASE64 = "A";
    private static final String PLAINTEXT = "secret";

    private static SecretKey aesKey;
    private static KeyPair rsaKeyPair;

    @BeforeAll
    static void setUp() throws Exception {
        org.apache.xml.security.Init.init();
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        aesKey = kg.generateKey();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        rsaKeyPair = kpg.generateKeyPair();
    }

    // ---------------------------------------------------------------- EncryptedData

    @Test
    void testWellFormedEncryptedDataDecrypts() throws Exception {
        Document doc = encryptedDataDocument();
        assertEquals(PLAINTEXT, decryptData(doc).getDocumentElement().getTextContent());
    }

    @Test
    void testMalformedEncryptedDataCipherValue() throws Exception {
        Document doc = encryptedDataDocument();
        setText(doc, XENC, "CipherValue", BAD_BASE64);
        assertThrows(XMLEncryptionException.class, () -> decryptData(doc));
    }

    @Test
    void testTooShortEncryptedDataCipherValue() throws Exception {
        // Valid base64, but shorter than the IV
        Document doc = encryptedDataDocument();
        setText(doc, XENC, "CipherValue", "AAAA");
        assertThrows(XMLEncryptionException.class, () -> decryptData(doc));
    }

    @Test
    void testMalformedEncryptedDataCipherValueDecryptToByteArray() throws Exception {
        Document doc = encryptedDataDocument();
        setText(doc, XENC, "CipherValue", BAD_BASE64);
        XMLCipher cipher = XMLCipher.getInstance();
        cipher.init(XMLCipher.DECRYPT_MODE, aesKey);
        Element encryptedData = getEncryptedData(doc);
        assertThrows(XMLEncryptionException.class, () -> cipher.decryptToByteArray(encryptedData));
    }

    @ParameterizedTest
    @ValueSource(strings = {"abc", "", "   "})
    void testMalformedKeySize(String keySize) throws Exception {
        Document doc = encryptedDataDocument();
        Element encryptionMethod = (Element) doc.getElementsByTagNameNS(XENC, "EncryptionMethod").item(0);
        Element keySizeElement = doc.createElementNS(XENC, "xenc:KeySize");
        if (!keySize.isEmpty()) {
            keySizeElement.setTextContent(keySize);
        }
        encryptionMethod.appendChild(keySizeElement);

        XMLCipher cipher = XMLCipher.getInstance();
        cipher.init(XMLCipher.DECRYPT_MODE, aesKey);
        Element encryptedData = getEncryptedData(doc);
        assertThrows(XMLEncryptionException.class, () -> cipher.loadEncryptedData(doc, encryptedData));
        assertThrows(XMLEncryptionException.class, () -> cipher.doFinal(doc, encryptedData));
    }

    // ---------------------------------------------------------------- EncryptedKey

    @Test
    void testWellFormedEncryptedKeyDecrypts() throws Exception {
        assertNotNull(decryptKey(encryptedKeyDocument()));
    }

    @Test
    void testMalformedEncryptedKeyCipherValue() throws Exception {
        Document doc = encryptedKeyDocument();
        setText(doc, XENC, "CipherValue", BAD_BASE64);
        assertThrows(XMLEncryptionException.class, () -> decryptKey(doc));
    }

    @Test
    void testMalformedOAEPparams() throws Exception {
        Document doc = encryptedKeyDocument();
        addOAEPparams(doc, BAD_BASE64);
        assertThrows(XMLEncryptionException.class, () -> decryptKey(doc));
    }

    @Test
    void testEmptyOAEPparamsIsAnEmptyOctetString() throws Exception {
        // xs:base64Binary allows an empty value, which is equivalent to the default (empty) P source
        Document doc = encryptedKeyDocument();
        addOAEPparams(doc, null);
        assertNotNull(decryptKey(doc));
    }

    @Test
    void testEmptyCarriedKeyName() throws Exception {
        // xs:string allows an empty value
        Document doc = encryptedKeyDocument();
        doc.getDocumentElement().appendChild(doc.createElementNS(XENC, "xenc:CarriedKeyName"));
        XMLCipher cipher = XMLCipher.getInstance();
        cipher.init(XMLCipher.UNWRAP_MODE, rsaKeyPair.getPrivate());
        EncryptedKey encryptedKey = cipher.loadEncryptedKey(doc, doc.getDocumentElement());
        assertEquals("", encryptedKey.getCarriedName());
    }

    @ParameterizedTest
    @ValueSource(strings = {"Salt", "Info"})
    void testMalformedHKDFParameter(String localName) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair recipient = kpg.generateKeyPair();

        Document doc = newDocument();
        HKDFParams kdf = HKDFParams.createBuilder(
                KeyUtils.getAESKeyBitSizeForWrapAlgorithm(XMLCipher.AES_128_KeyWrap),
                XMLSignature.ALGO_ID_MAC_HMAC_SHA256)
            .salt(new byte[] {1, 2, 3, 4, 5, 6, 7, 8})
            .info("info".getBytes(StandardCharsets.UTF_8))
            .build();
        KeyAgreementParameters params = new KeyAgreementParameters(
            KeyAgreementParameters.ActorType.ORIGINATOR, EncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES, kdf);
        XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.AES_128_KeyWrap);
        keyCipher.init(XMLCipher.WRAP_MODE, recipient.getPublic());
        EncryptedKey encryptedKey = keyCipher.encryptKey(doc, aesKey, params, null);
        doc.appendChild(keyCipher.martial(doc, encryptedKey));
        Document reparsed = reparse(doc);

        setText(reparsed, Constants.XML_DSIG_NS_MORE_21_04, localName, BAD_BASE64);

        XMLCipher cipher = XMLCipher.getInstance();
        cipher.init(XMLCipher.UNWRAP_MODE, recipient.getPrivate());
        EncryptedKey loaded = cipher.loadEncryptedKey(reparsed, reparsed.getDocumentElement());
        assertThrows(XMLEncryptionException.class, () -> cipher.decryptKey(loaded, XMLCipher.AES_128));
    }

    // ---------------------------------------------------------------- helpers

    private static Document encryptedDataDocument() throws Exception {
        Document doc = newDocument();
        Element root = doc.createElement("root");
        root.setTextContent(PLAINTEXT);
        doc.appendChild(root);
        XMLCipher cipher = XMLCipher.getInstance(XMLCipher.AES_128);
        cipher.init(XMLCipher.ENCRYPT_MODE, aesKey);
        cipher.doFinal(doc, root, false);
        return reparse(doc);
    }

    private static Document encryptedKeyDocument() throws Exception {
        Document doc = newDocument();
        XMLCipher cipher = XMLCipher.getInstance(XMLCipher.RSA_OAEP);
        cipher.init(XMLCipher.WRAP_MODE, rsaKeyPair.getPublic());
        EncryptedKey encryptedKey = cipher.encryptKey(doc, aesKey);
        doc.appendChild(cipher.martial(doc, encryptedKey));
        return reparse(doc);
    }

    private static Document decryptData(Document doc) throws Exception {
        XMLCipher cipher = XMLCipher.getInstance();
        cipher.init(XMLCipher.DECRYPT_MODE, aesKey);
        Element encryptedData = getEncryptedData(doc);
        EncryptedData loaded = cipher.loadEncryptedData(doc, encryptedData);
        assertNotNull(loaded);
        return cipher.doFinal(doc, encryptedData);
    }

    private static Key decryptKey(Document doc) throws Exception {
        XMLCipher cipher = XMLCipher.getInstance();
        cipher.init(XMLCipher.UNWRAP_MODE, rsaKeyPair.getPrivate());
        EncryptedKey encryptedKey = cipher.loadEncryptedKey(doc, doc.getDocumentElement());
        return cipher.decryptKey(encryptedKey, XMLCipher.AES_128);
    }

    private static void addOAEPparams(Document doc, String value) {
        Element encryptionMethod = (Element) doc.getElementsByTagNameNS(XENC, "EncryptionMethod").item(0);
        Element oaepParams = doc.createElementNS(XENC, "xenc:OAEPparams");
        if (value != null) {
            oaepParams.setTextContent(value);
        }
        encryptionMethod.insertBefore(oaepParams, encryptionMethod.getFirstChild());
    }

    private static Element getEncryptedData(Document doc) {
        return (Element) doc.getElementsByTagNameNS(XENC, "EncryptedData").item(0);
    }

    private static void setText(Document doc, String namespace, String localName, String value) {
        Element element = (Element) doc.getElementsByTagNameNS(namespace, localName).item(0);
        assertNotNull(element, "expected a <" + localName + "> element to mutate");
        while (element.hasChildNodes()) {
            element.removeChild(element.getFirstChild());
        }
        element.appendChild(doc.createTextNode(value));
    }

    private static Document newDocument() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder().newDocument();
    }

    private static Document reparse(Document doc) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        XMLUtils.outputDOM(doc, bos);
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder().parse(new ByteArrayInputStream(bos.toByteArray()));
    }
}
