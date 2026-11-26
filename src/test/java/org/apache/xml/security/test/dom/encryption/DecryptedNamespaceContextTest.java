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

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Namespace declarations in scope around encrypted content are copied into the context used to
 * parse the decrypted content. Their values must be escaped there (DOM API).
 */
class DecryptedNamespaceContextTest {

    static {
        org.apache.xml.security.Init.init();
    }

    private static SecretKey aesKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }

    /** Encrypts the "secret" element (Element type) and serialises the document. */
    private static String encrypt(String xml, SecretKey key) throws Exception {
        Document doc = XMLUtils.read(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)), false);
        XMLCipher cipher = XMLCipher.getInstance(XMLCipher.AES_128);
        cipher.init(XMLCipher.ENCRYPT_MODE, key);
        cipher.doFinal(doc, (Element) doc.getElementsByTagNameNS("*", "secret").item(0), false);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        TransformerFactory.newInstance().newTransformer().transform(new DOMSource(doc), new StreamResult(baos));
        return baos.toString(StandardCharsets.UTF_8.name());
    }

    private static Document decrypt(String encrypted, SecretKey key) throws Exception {
        Document doc = XMLUtils.read(new ByteArrayInputStream(encrypted.getBytes(StandardCharsets.UTF_8)), false);
        Element encryptedData = (Element) doc.getElementsByTagNameNS(
            EncryptionConstants.EncryptionSpecNS, EncryptionConstants._TAG_ENCRYPTEDDATA).item(0);
        XMLCipher cipher = XMLCipher.getInstance();
        cipher.init(XMLCipher.DECRYPT_MODE, key);
        cipher.doFinal(doc, encryptedData);
        return doc;
    }

    /** Namespace values added around the encrypted content must not inject markup into it. */
    @Test
    void testNamespaceValuesDoNotInjectMarkup() throws Exception {
        SecretKey key = aesKey();
        String encrypted = encrypt(
                "<root><secret>value</secret></root>", key)
            .replaceFirst("<root", "<root xmlns:a=\"--&gt;\" xmlns:b=\"x&quot;&gt;&lt;evil/&gt;&lt;!--\"");

        Document decrypted = decrypt(encrypted, key);

        assertEquals(0, decrypted.getElementsByTagNameNS("*", "evil").getLength());
        assertEquals("value", decrypted.getElementsByTagNameNS("*", "secret").item(0).getTextContent());
    }

    /** A namespace URI containing characters that must be escaped keeps its value. */
    @Test
    void testNamespaceUriWithSpecialCharacters() throws Exception {
        SecretKey key = aesKey();
        String encrypted = encrypt(
            "<root xmlns:p=\"urn:a&amp;b&lt;c&quot;d&#10;e\"><p:secret>value</p:secret></root>", key);

        Document decrypted = decrypt(encrypted, key);

        Element secret = (Element) decrypted.getElementsByTagNameNS("*", "secret").item(0);
        assertEquals("urn:a&b<c\"d\ne", secret.getNamespaceURI());
        assertEquals("value", secret.getTextContent());
    }
}
