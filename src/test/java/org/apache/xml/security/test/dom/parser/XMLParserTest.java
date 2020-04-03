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
package org.apache.xml.security.test.dom.parser;


import java.io.InputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test that we can plug in a custom XMLParser implementation via a system property
 */
public class XMLParserTest {

    static org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(XMLParserTest.class);

    private KeyPair rsaKeyPair;

    @BeforeAll
    public static void setup() {
        System.setProperty("org.apache.xml.security.XMLParser", CustomXMLParserImpl.class.getName());
    }

    @AfterAll
    public static void cleanup() {
        System.clearProperty("org.apache.xml.security.XMLParser");
    }

    public XMLParserTest() throws Exception {
        org.apache.xml.security.Init.init();
        rsaKeyPair = KeyPairGenerator.getInstance("RSA").genKeyPair();
    }

    @org.junit.jupiter.api.Test
    public void testRSA_SHA1() throws Exception {
        assertFalse(CustomXMLParserImpl.isCalled());

        // Read in plaintext document
        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = XMLUtils.read(sourceDocument, false);

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        sign(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1, document, localNames, rsaKeyPair.getPrivate());
        // XMLUtils.outputDOM(document, System.out);
        verify(document, rsaKeyPair.getPublic(), localNames);

        assertTrue(CustomXMLParserImpl.isCalled());
    }

    private XMLSignature sign(
            String algorithm,
            Document document,
            List<String> localNames,
            Key signingKey
    ) throws Exception {
        return sign(algorithm, document, localNames, signingKey, null);
    }

    private XMLSignature sign(
            String algorithm,
            Document document,
            List<String> localNames,
            Key signingKey,
            AlgorithmParameterSpec parameterSpec
    ) throws Exception {
        String c14nMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";
        XMLSignature sig = new XMLSignature(document, "", algorithm, 0, c14nMethod, null, parameterSpec);

        Element root = document.getDocumentElement();
        root.appendChild(sig.getElement());

        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());

        for (String localName : localNames) {
            String expression = "//*[local-name()='" + localName + "']";
            NodeList elementsToSign =
                    (NodeList) xpath.evaluate(expression, document, XPathConstants.NODESET);
            for (int i = 0; i < elementsToSign.getLength(); i++) {
                Element elementToSign = (Element)elementsToSign.item(i);
                assertNotNull(elementToSign);
                String id = UUID.randomUUID().toString();
                elementToSign.setAttributeNS(null, "Id", id);
                elementToSign.setIdAttributeNS(null, "Id", true);

                Transforms transforms = new Transforms(document);
                transforms.addTransform(c14nMethod);
                String digestMethod = "http://www.w3.org/2000/09/xmldsig#sha1";
                sig.addDocument("#" + id, transforms, digestMethod);
            }
        }

        sig.sign(signingKey);

        String expression = "//ds:Signature[1]";
        Element sigElement =
                (Element) xpath.evaluate(expression, document, XPathConstants.NODE);
        assertNotNull(sigElement);

        return sig;
    }

    private void verify(
            Document document,
            Key key,
            List<String> localNames
    ) throws Exception {
        verify(document, key, localNames, true);
    }

    private void verify(
            Document document,
            Key key,
            List<String> localNames,
            boolean secureValidation
    ) throws Exception {
        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());

        String expression = "//dsig:Signature[1]";
        Element sigElement =
                (Element) xpath.evaluate(expression, document, XPathConstants.NODE);
        assertNotNull(sigElement);

        for (String name : localNames) {
            expression = "//*[local-name()='" + name + "']";
            Element signedElement =
                    (Element) xpath.evaluate(expression, document, XPathConstants.NODE);
            assertNotNull(signedElement);
            signedElement.setIdAttributeNS(null, "Id", true);
        }

        XMLSignature signature = new XMLSignature(sigElement, "", secureValidation);

        assertTrue(signature.checkSignatureValue(key));
    }

}