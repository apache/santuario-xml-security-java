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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;

import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * A malformed (non-base64) CipherValue in an inbound EncryptedKey must surface from the StAX
 * reader as an XMLStreamException, not as an unchecked IllegalArgumentException.
 */
class MalformedEncryptedKeyTest {

    private static KeyPair rsaKeyPair;

    @BeforeAll
    static void setUp() throws Exception {
        org.apache.xml.security.Init.init();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        rsaKeyPair = kpg.generateKeyPair();
    }

    @Test
    void testWellFormedEncryptedKeyDecrypts() throws Exception {
        byte[] encrypted = encrypt();
        assertDoesNotThrow(() -> readAll(encrypted));
    }

    @Test
    void testMalformedEncryptedKeyCipherValue() throws Exception {
        Document doc = parse(encrypt());
        // The EncryptedKey (inside EncryptedData/KeyInfo) precedes the EncryptedData CipherData in document order
        Element cipherValue = (Element) doc.getElementsByTagNameNS(
            EncryptionConstants.EncryptionSpecNS, "CipherValue").item(0);
        assertEquals("EncryptedKey", cipherValue.getParentNode().getParentNode().getLocalName());
        while (cipherValue.hasChildNodes()) {
            cipherValue.removeChild(cipherValue.getFirstChild());
        }
        cipherValue.appendChild(doc.createTextNode("A"));
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        XMLUtils.outputDOM(doc, bos);

        assertThrows(XMLStreamException.class, () -> readAll(bos.toByteArray()));
    }

    private static byte[] encrypt() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);

        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setActions(List.of(XMLSecurityConstants.ENCRYPTION));
        properties.setEncryptionKey(kg.generateKey());
        properties.setEncryptionTransportKey(rsaKeyPair.getPublic());
        properties.setEncryptionSymAlgorithm(XMLCipher.AES_128);
        properties.setEncryptionKeyTransportAlgorithm(XMLCipher.RSA_OAEP);
        properties.addEncryptionPart(new SecurePart(new QName("data"), SecurePart.Modifier.Element));

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        XMLStreamWriter writer = XMLSec.getOutboundXMLSec(properties).processOutMessage(bos, StandardCharsets.UTF_8.name());
        writer.writeStartElement("root");
        writer.writeStartElement("data");
        writer.writeCharacters("secret");
        writer.writeEndElement();
        writer.writeEndElement();
        writer.close();
        return bos.toByteArray();
    }

    private static void readAll(byte[] xml) throws Exception {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setDecryptionKey(rsaKeyPair.getPrivate());
        XMLStreamReader reader = XMLSec.getInboundWSSec(properties).processInMessage(
            XMLInputFactory.newInstance().createXMLStreamReader(new ByteArrayInputStream(xml)));
        while (reader.hasNext()) {
            reader.next();
        }
    }

    private static Document parse(byte[] xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xml));
    }
}
