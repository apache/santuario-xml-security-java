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
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.stax.config.Init;
import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.test.stax.utils.StAX2DOM;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * A set of test-cases for Signature verification.
 *
 * These are separated out from SignatureVerificationTest as we have to change the default configuration to set
 * "MaximumAllowedTransformsPerReference" to "0".
 */
public class SignatureVerificationMaxTransTest extends AbstractSignatureVerificationTest {

    private TransformerFactory transformerFactory = TransformerFactory.newInstance();

    @BeforeAll
    public static void setup() throws Exception {
        XMLSec.init();
        Init.init(SignatureVerificationMaxTransTest.class.getClassLoader().getResource("security-config-max-trans-per.xml").toURI(),
                SignatureVerificationMaxTransTest.class);
        org.apache.xml.security.Init.init();
    }

    @Test
    public void testMaximumAllowedTransformsPerReference() throws Exception {
        // Read in plaintext document
        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        // Set up the Key
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");

        // Sign using DOM
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        XMLSignature sig = signUsingDOM(
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1", document, localNames, key
        );

        // Add KeyInfo
        sig.addKeyInfo(cert);

        // Convert Document to a Stream Reader
        javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(baos));

        XMLStreamReader xmlStreamReader = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            xmlStreamReader = xmlInputFactory.createXMLStreamReader(is);
        }

        // Verify signature
        XMLSecurityProperties properties = new XMLSecurityProperties();
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        TestSecurityEventListener securityEventListener = new TestSecurityEventListener();
        XMLStreamReader securityStreamReader =
                inboundXMLSec.processInMessage(xmlStreamReader, null, securityEventListener);

        try {
            StAX2DOM.readDoc(securityStreamReader);
            fail("Exception expected");
        } catch (XMLStreamException e) {
            assertTrue(e.getCause() instanceof XMLSecurityException);
            assertEquals("1 transforms are contained in the Reference, maximum 0 are allowed. You can raise the maximum " +
                            "via the \"MaximumAllowedTransformsPerReference\" property in the configuration.",
                    e.getCause().getMessage());
        }
    }
}