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
package org.apache.xml.security.test.stax.signature;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.test.stax.utils.StAX2DOM;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

/**
 * A signature created with the DOM API, whose Reference uses Canonical XML 1.1 over an element
 * carrying xml:id and xml:base, must verify with the StAX API.
 */
class C14N11XmlBaseSignatureTest extends AbstractSignatureVerificationTest {

    @Test
    void testDOMSignatureWithC14N11OverXmlBaseVerifies() throws Exception {
        String xml = "<root xml:base=\"http://host/a/\"><signed xml:id=\"x1\" xml:base=\"b/\">"
            + "<child>value</child></signed></root>";
        Document document = XMLUtils.read(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)), false);

        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        X509Certificate cert = (X509Certificate) keyStore.getCertificate("transmitter");

        List<String> localNames = new ArrayList<>();
        localNames.add("signed");
        // C14N 1.1 for SignedInfo and as the Reference transform
        signUsingDOM("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", document, localNames, key,
                     "http://www.w3.org/2006/12/xml-c14n11");

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        TransformerFactory.newInstance().newTransformer().transform(new DOMSource(document), new StreamResult(baos));

        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setSignatureVerificationKey(cert.getPublicKey());
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        XMLStreamReader reader = xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray()));
        StAX2DOM.readDoc(inboundXMLSec.processInMessage(reader, null, null));
    }
}
