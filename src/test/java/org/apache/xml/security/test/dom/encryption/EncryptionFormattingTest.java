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

import org.apache.xml.security.Init;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.formatting.FormattingChecker;
import org.apache.xml.security.formatting.FormattingCheckerFactory;
import org.apache.xml.security.formatting.FormattingTest;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * This is a {@link FormattingTest}, it is expected to be run with different system properties
 * to check various formatting configurations.
 *
 * The test uses AES-256-GCM encryption with RSA-OAEP key wrapping to generate a document containing encrypted data
 * and data encryption key.
 */
@FormattingTest
public class EncryptionFormattingTest {
    private final Random random = new Random();
    private final FormattingChecker formattingChecker;
    private KeyStore keyStore;
    private XPath xpath;

    public EncryptionFormattingTest() throws Exception {
        Init.init();
        formattingChecker = FormattingCheckerFactory.getFormattingChecker();
        keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = getClass()
                .getResourceAsStream("/org/apache/xml/security/samples/input/rsa.p12")) {
            keyStore.load(in, "xmlsecurity".toCharArray());
        } catch (IOException | GeneralSecurityException e) {
            fail("Cannot load test keystore", e);
        }

        XPathFactory xPathFactory = XPathFactory.newInstance();
        xpath = xPathFactory.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext(Map.of(
                "xenc", "http://www.w3.org/2001/04/xmlenc#"
        )));
    }

    @Test
    public void testEncryptedFormatting() throws Exception {
        /* this test checks formatting of base64binary values */
        byte[] testData = new byte[128]; // long enough for line breaks
        random.nextBytes(testData);

        Document doc = createDocument(testData);

        String str;
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            XMLUtils.outputDOM(doc, baos);
            str = baos.toString(StandardCharsets.UTF_8);
            formattingChecker.checkDocument(str);
        }

        NodeList elements = (NodeList) xpath.evaluate("//xenc:CipherData", doc, XPathConstants.NODESET);
        assertEquals(2, elements.getLength());
        formattingChecker.checkBase64Value(elements.item(0).getTextContent());
        formattingChecker.checkBase64Value(elements.item(1).getTextContent());
    }

    @Test
    public void testEncryptDecrypt() throws Exception {
        /* this test ensures that the encrypted data can be processed with various formatting settings */
        byte[] testData = new byte[128]; // long enough for line breaks
        random.nextBytes(testData);

        Document doc = createDocument(testData);
        Element encryptedKeyElement =
                (Element) xpath.evaluate("//xenc:EncryptedKey[1]", doc, XPathConstants.NODE);
        Element encryptedDataElement =
                (Element) xpath.evaluate("//xenc:EncryptedData[1]", doc, XPathConstants.NODE);

        Key kek = keyStore.getKey("test", "xmlsecurity".toCharArray());
        XMLCipher keyCipher = XMLCipher.getInstance("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
                null, "http://www.w3.org/2001/04/xmlenc#sha512");
        keyCipher.init(XMLCipher.UNWRAP_MODE, kek);
        EncryptedKey encryptedKey = keyCipher.loadEncryptedKey(doc, encryptedKeyElement);
        Key sessionKey = keyCipher.decryptKey(encryptedKey, "http://www.w3.org/2009/xmlenc11#aes256-gcm");

        XMLCipher dataCipher = XMLCipher.getInstance("http://www.w3.org/2009/xmlenc11#aes256-gcm");
        dataCipher.init(XMLCipher.DECRYPT_MODE, sessionKey);
        byte[] decryptedData = dataCipher.decryptToByteArray(encryptedDataElement);

        assertArrayEquals(testData, decryptedData);
    }

    private Key generateSessionKey() {
        byte[] keyBytes = new byte[32];
        random.nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, "AES");
    }

    private Document createDocument(byte[] data) throws Exception {
        Document doc = TestUtils.newDocument();
        Key sessionKey = generateSessionKey();
        Certificate cert = keyStore.getCertificate("test");

        XMLCipher keyCipher = XMLCipher.getInstance("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
                null, "http://www.w3.org/2001/04/xmlenc#sha512");
        keyCipher.init(XMLCipher.WRAP_MODE, cert.getPublicKey());
        EncryptedKey encryptedKey = keyCipher.encryptKey(doc, sessionKey);

        XMLCipher dataCipher = XMLCipher.getInstance("http://www.w3.org/2009/xmlenc11#aes256-gcm");
        dataCipher.init(XMLCipher.ENCRYPT_MODE, sessionKey);

        EncryptedData builder = dataCipher.getEncryptedData();
        KeyInfo builderKeyInfo = builder.getKeyInfo();
        if (builderKeyInfo == null) {
            builderKeyInfo = new KeyInfo(doc);
            builder.setKeyInfo(builderKeyInfo);
        }
        builderKeyInfo.add(encryptedKey);

        EncryptedData encData = dataCipher.encryptData(doc, null, new ByteArrayInputStream(data));
        Element encDataElement = dataCipher.martial(encData);

        doc.appendChild(encDataElement);

        return doc;
    }
}
