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
package org.apache.xml.security.test.stax.encryption;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.stax.utils.StAX2DOM;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * An EncryptedKey whose key transport decrypts to a key of the wrong length must fail in the same
 * way as one that does not decrypt at all, so that the outcome does not reveal whether the private
 * key operation produced a well-formed plaintext.
 */
class EncryptedKeyLengthOracleTest {

    private static final String RSA_OAEP = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
    private static final String AES_128_GCM = "http://www.w3.org/2009/xmlenc11#aes128-gcm";

    static {
        org.apache.xml.security.Init.init();
    }

    private final XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();

    /**
     * Encrypts a document with aes128-gcm and an RSA-OAEP EncryptedKey, then replaces the
     * EncryptedKey's CipherValue with the given bytes.
     */
    private byte[] encryptWithKeyCipherValue(PublicKey publicKey, byte[] keyCipherValue) throws Exception {
        Document doc = XMLUtils.read(new ByteArrayInputStream(
            "<root><secret>value</secret></root>".getBytes(StandardCharsets.UTF_8)), false);
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey contentKey = keyGen.generateKey();

        XMLCipher keyCipher = XMLCipher.getInstance(RSA_OAEP);
        keyCipher.init(XMLCipher.WRAP_MODE, publicKey);
        EncryptedKey encryptedKey = keyCipher.encryptKey(doc, contentKey);

        XMLCipher dataCipher = XMLCipher.getInstance(AES_128_GCM);
        dataCipher.init(XMLCipher.ENCRYPT_MODE, contentKey);
        EncryptedData encryptedData = dataCipher.getEncryptedData();
        KeyInfo keyInfo = new KeyInfo(doc);
        keyInfo.add(encryptedKey);
        encryptedData.setKeyInfo(keyInfo);
        Element secret = (Element) doc.getElementsByTagName("secret").item(0);
        dataCipher.doFinal(doc, secret, false);

        // Replace the EncryptedKey's CipherValue
        org.w3c.dom.NodeList cipherValues =
            doc.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#", "CipherValue");
        for (int i = 0; i < cipherValues.getLength(); i++) {
            Element cv = (Element) cipherValues.item(i);
            if ("EncryptedKey".equals(cv.getParentNode().getParentNode().getLocalName())) {
                cv.setTextContent(Base64.getEncoder().encodeToString(keyCipherValue));
            }
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        TransformerFactory.newInstance().newTransformer().transform(new DOMSource(doc), new StreamResult(baos));
        return baos.toByteArray();
    }

    private Throwable decryptFailure(byte[] encrypted, PrivateKey privateKey) throws Exception {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setDecryptionKey(privateKey);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        XMLStreamReader reader = xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(encrypted));
        XMLStreamException ex = assertThrows(XMLStreamException.class,
            () -> StAX2DOM.readDoc(inboundXMLSec.processInMessage(reader, null, null)));
        Throwable root = ex;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        return root;
    }

    private static byte[] rsaOaepEncrypt(PublicKey publicKey, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plaintext);
    }

    @Test
    void testWrongLengthKeyIsIndistinguishableFromFailedDecryption() throws Exception {
        KeyStore keyStore = XmlSecTestEnvironment.getTransmitterKeyStore();
        X509Certificate cert = (X509Certificate) keyStore.getCertificate("transmitter");
        PrivateKey privateKey = (PrivateKey) keyStore.getKey("transmitter",
            XmlSecTestEnvironment.TRANSMITTER_KS_PASSWORD.toCharArray());
        PublicKey publicKey = cert.getPublicKey();

        // A CipherValue that does not decrypt under the private key
        byte[] garbage = new byte[256];
        new SecureRandom().nextBytes(garbage);
        Throwable failedDecryption = decryptFailure(encryptWithKeyCipherValue(publicKey, garbage), privateKey);

        // A CipherValue that decrypts correctly, but to a key that is not 16 bytes long
        byte[] wrongLengthKey = rsaOaepEncrypt(publicKey, new byte[7]);
        Throwable wrongLength = decryptFailure(encryptWithKeyCipherValue(publicKey, wrongLengthKey), privateKey);

        assertEquals(failedDecryption.getClass(), wrongLength.getClass(),
            "a wrong-length key must fail like a failed key decryption");

        // An over-long key too
        byte[] overlongKey = rsaOaepEncrypt(publicKey, new byte[40]);
        Throwable overlong = decryptFailure(encryptWithKeyCipherValue(publicKey, overlongKey), privateKey);
        assertEquals(failedDecryption.getClass(), overlong.getClass(),
            "an over-long key must fail like a failed key decryption");
    }
}
