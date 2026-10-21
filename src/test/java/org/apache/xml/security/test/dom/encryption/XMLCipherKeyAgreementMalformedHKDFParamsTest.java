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
import java.security.PrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyGenerator;
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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The HKDF {@code Salt} and {@code Info} elements of an ECDH-ES {@code KeyDerivationMethod} are
 * read from the (untrusted) message and base64-decoded on the decrypt path. Malformed base64
 * there must be rejected as {@link XMLEncryptionException}, the exception type the decrypt API
 * declares, rather than escaping as the {@code IllegalArgumentException} thrown by
 * {@code Base64.Decoder}, which a caller handling the declared type would not catch.
 */
class XMLCipherKeyAgreementMalformedHKDFParamsTest {

    private static final String PLAINTEXT = "CardNumber:4019111111111111";

    @BeforeAll
    static void setUp() {
        org.apache.xml.security.Init.init();
    }

    /** Positive control: the same round trip decrypts when the parameters are untouched. */
    @Test
    void testWellFormedHKDFParamsDecrypt() throws Exception {
        KeyPair recipient = generateRecipientKeyPair();
        Document encDoc = parse(encryptToRecipient(recipient));
        Document decrypted = decryptDocument(encDoc, recipient.getPrivate());
        assertEquals(PLAINTEXT, decrypted.getDocumentElement().getTextContent());
    }

    @ParameterizedTest
    @CsvSource({
        "Salt,!!!not-base64!!!",
        "Info,@@@@"
    })
    void testMalformedHKDFParamRejected(String localName, String badText) throws Exception {
        KeyPair recipient = generateRecipientKeyPair();
        Document encDoc = parse(encryptToRecipient(recipient));

        Element target = (Element) encDoc.getElementsByTagNameNS(Constants.XML_DSIG_NS_MORE_21_04, localName).item(0);
        assertNotNull(target, "expected an HKDF <" + localName + "> element to mutate");
        while (target.hasChildNodes()) {
            target.removeChild(target.getFirstChild());
        }
        target.appendChild(encDoc.createTextNode(badText));

        assertThrows(XMLEncryptionException.class, () -> decryptDocument(encDoc, recipient.getPrivate()));
    }

    private static KeyPair generateRecipientKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    /** ECDH-ES key agreement with HKDF (explicit Salt and Info) wrapping an AES-128 CEK; AES-256-GCM content. */
    private static byte[] encryptToRecipient(KeyPair recipient) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().newDocument();
        Element root = doc.createElement("PaymentInfo");
        root.setTextContent(PLAINTEXT);
        doc.appendChild(root);

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        Key cek = kg.generateKey();

        String keyWrapAlgorithm = XMLCipher.AES_128_KeyWrap;
        int keyBitLen = KeyUtils.getAESKeyBitSizeForWrapAlgorithm(keyWrapAlgorithm);
        HKDFParams kdf = HKDFParams.createBuilder(keyBitLen, XMLSignature.ALGO_ID_MAC_HMAC_SHA256)
                .salt(new byte[]{1, 2, 3, 4, 5, 6, 7, 8})
                .info("test-info-data".getBytes(StandardCharsets.UTF_8))
                .build();
        AlgorithmParameterSpec params = new KeyAgreementParameters(
                KeyAgreementParameters.ActorType.ORIGINATOR,
                EncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES,
                kdf);

        XMLCipher keyCipher = XMLCipher.getInstance(keyWrapAlgorithm);
        keyCipher.init(XMLCipher.WRAP_MODE, recipient.getPublic());
        EncryptedKey encryptedKey = keyCipher.encryptKey(doc, cek, params, null);

        XMLCipher dataCipher = XMLCipher.getInstance(XMLCipher.AES_256_GCM);
        dataCipher.init(XMLCipher.ENCRYPT_MODE, cek);
        EncryptedData encryptedData = dataCipher.getEncryptedData();
        KeyInfo keyInfo = new KeyInfo(doc);
        keyInfo.add(encryptedKey);
        encryptedData.setKeyInfo(keyInfo);
        doc = dataCipher.doFinal(doc, root, false);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        javax.xml.transform.TransformerFactory.newInstance().newTransformer().transform(
                new javax.xml.transform.dom.DOMSource(doc),
                new javax.xml.transform.stream.StreamResult(bos));
        return bos.toByteArray();
    }

    private static Document parse(byte[] xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xml));
    }

    /** The full decrypt path: load the EncryptedData, derive and unwrap the CEK via the recipient's key, decrypt. */
    private static Document decryptDocument(Document encDoc, PrivateKey recipientKey) throws Exception {
        NodeList encDataNodes = encDoc.getElementsByTagNameNS(EncryptionConstants.EncryptionSpecNS, "EncryptedData");
        Element encDataElem = (Element) encDataNodes.item(0);
        XMLCipher decryptCipher = XMLCipher.getInstance();
        decryptCipher.init(XMLCipher.DECRYPT_MODE, null);
        EncryptedData encData = decryptCipher.loadEncryptedData(encDoc, encDataElem);
        EncryptedKey ek = encData.getKeyInfo().itemEncryptedKey(0);
        XMLCipher unwrapCipher = XMLCipher.getInstance();
        unwrapCipher.init(XMLCipher.UNWRAP_MODE, recipientKey);
        Key cek = unwrapCipher.decryptKey(ek, encData.getEncryptionMethod().getAlgorithm());
        decryptCipher.init(XMLCipher.DECRYPT_MODE, cek);
        return decryptCipher.doFinal(encDoc, encDataElem);
    }
}
