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
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.test.stax.utils.StAX2DOM;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * SignedInfo must be canonicalized with a canonicalization algorithm. A CanonicalizationMethod
 * that names some other transform must be rejected, as the DOM API does.
 */
class SignedInfoCanonicalizationMethodTest extends AbstractSignatureVerificationTest {

    @ParameterizedTest
    @ValueSource(strings = {
        "http://www.w3.org/2000/09/xmldsig#base64",
        "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
    })
    void testNonCanonicalizationMethodRejected(String algorithm) throws Exception {
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
            "default".toCharArray()
        );
        PrivateKey key = (PrivateKey)keyStore.getKey("transmitter", "default".toCharArray());
        X509Certificate cert = (X509Certificate) keyStore.getCertificate("transmitter");

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        signUsingDOM("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", document, localNames, key);

        Element c14nMethod = (Element) document.getElementsByTagNameNS(
            "http://www.w3.org/2000/09/xmldsig#", "CanonicalizationMethod").item(0);
        c14nMethod.setAttributeNS(null, "Algorithm", algorithm);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        TransformerFactory.newInstance().newTransformer().transform(new DOMSource(document), new StreamResult(baos));

        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setSignatureVerificationKey(cert.getPublicKey());
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        XMLStreamReader reader = xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray()));

        XMLStreamException ex = assertThrows(XMLStreamException.class,
            () -> StAX2DOM.readDoc(inboundXMLSec.processInMessage(reader, null, null)));
        assertTrue(ex.getMessage().contains("No canonicalizer found with URI " + algorithm), ex.getMessage());
    }
}
