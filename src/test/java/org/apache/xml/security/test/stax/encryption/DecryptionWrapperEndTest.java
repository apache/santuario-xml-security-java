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
import java.time.Duration;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.test.stax.utils.StAX2DOM;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The end of decrypted content must be found reliably, and the decryption thread must not be
 * left running when the decrypted content is not read to its end.
 */
class DecryptionWrapperEndTest {

    private static final String DECRYPTION_THREAD = "decryption thread";

    static {
        org.apache.xml.security.Init.init();
    }

    private final XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();

    private static byte[] encrypt(String xml, SecretKey key, String algorithm) throws Exception {
        Document doc = XMLUtils.read(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)), false);
        XMLCipher cipher = XMLCipher.getInstance(algorithm);
        cipher.init(XMLCipher.ENCRYPT_MODE, key);
        cipher.doFinal(doc, (Element) doc.getElementsByTagName("secret").item(0), false);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        TransformerFactory.newInstance().newTransformer().transform(new DOMSource(doc), new StreamResult(baos));
        return baos.toByteArray();
    }

    private Document decrypt(byte[] encrypted, SecretKey key) throws Exception {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setDecryptionKey(key);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        XMLStreamReader reader = xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(encrypted));
        return StAX2DOM.readDoc(inboundXMLSec.processInMessage(reader, null, null));
    }

    private static SecretKey aesKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }

    private static String padding() {
        StringBuilder pad = new StringBuilder();
        for (int i = 0; i < 20000; i++) {
            pad.append("0123456789");
        }
        return pad.toString();
    }

    private static Set<Thread> decryptionThreads() {
        return Thread.getAllStackTraces().keySet().stream()
            .filter(t -> DECRYPTION_THREAD.equals(t.getName()) && t.isAlive())
            .collect(Collectors.toSet());
    }

    /**
     * Decrypted content containing an element with the same name as the internal wrapper element
     * must be decrypted completely, without hanging.
     */
    @ParameterizedTest
    @ValueSource(strings = {
        "http://www.w3.org/2009/xmlenc11#aes128-gcm",
        "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
    })
    void testContentWithWrapperElementName(String algorithm) throws Exception {
        SecretKey key = aesKey();
        String pad = padding();
        byte[] encrypted = encrypt(
            "<root><secret><x:dummy xmlns:x=\"http://dummy\"/><pad>" + pad + "</pad></secret><after/></root>",
            key, algorithm);

        Document decrypted = assertTimeoutPreemptively(Duration.ofSeconds(60), () -> decrypt(encrypted, key));

        assertEquals(1, decrypted.getElementsByTagNameNS("http://dummy", "dummy").getLength());
        assertEquals(pad, decrypted.getElementsByTagName("pad").item(0).getTextContent());
        assertEquals(1, decrypted.getElementsByTagName("after").getLength());
    }

    /**
     * When processing of the decrypted content fails before it is read to its end, the decryption
     * thread must not stay blocked.
     */
    @Test
    void testDecryptionThreadEndsWhenProcessingFails() throws Exception {
        SecretKey key = aesKey();
        StringBuilder nested = new StringBuilder();
        for (int i = 0; i < 150; i++) {
            nested.append("<n>");
        }
        StringBuilder closing = new StringBuilder();
        for (int i = 0; i < 150; i++) {
            closing.append("</n>");
        }
        byte[] encrypted = encrypt(
            "<root><secret>" + nested + closing + "<pad>" + padding() + "</pad></secret></root>",
            key, "http://www.w3.org/2001/04/xmlenc#aes128-cbc");

        Set<Thread> before = decryptionThreads();
        assertThrows(XMLStreamException.class, () -> decrypt(encrypted, key));

        // the decryption thread must end soon after the failure
        long deadline = System.currentTimeMillis() + 10000;
        Set<Thread> leaked;
        do {
            leaked = decryptionThreads();
            leaked.removeAll(before);
            if (leaked.isEmpty()) {
                break;
            }
            Thread.sleep(100);
        } while (System.currentTimeMillis() < deadline);
        assertTrue(leaked.isEmpty(), "decryption thread still running: " + leaked);
    }
}
