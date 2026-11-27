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

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
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
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Encrypted content must decrypt whatever character encoding the document uses.
 */
class DecryptionDocumentEncodingTest {

    static {
        org.apache.xml.security.Init.init();
    }

    @ParameterizedTest
    @ValueSource(strings = {"UTF-8", "UTF-16", "ISO-8859-1", "IBM037"})
    void testDecryptInDocumentEncoding(String encoding) throws Exception {
        Document doc = XMLUtils.read(new ByteArrayInputStream(
            "<root><secret>value</secret></root>".getBytes(StandardCharsets.UTF_8)), false);
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();
        XMLCipher cipher = XMLCipher.getInstance(XMLCipher.AES_128_GCM);
        cipher.init(XMLCipher.ENCRYPT_MODE, key);
        cipher.doFinal(doc, (Element) doc.getElementsByTagName("secret").item(0), false);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.ENCODING, encoding);
        transformer.transform(new DOMSource(doc), new StreamResult(baos));

        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setDecryptionKey(key);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        XMLStreamReader reader = XMLInputFactory.newInstance().createXMLStreamReader(
            new ByteArrayInputStream(baos.toByteArray()));
        Document decrypted = StAX2DOM.readDoc(inboundXMLSec.processInMessage(reader, null, null));

        assertEquals("value", decrypted.getElementsByTagName("secret").item(0).getTextContent());
    }
}
