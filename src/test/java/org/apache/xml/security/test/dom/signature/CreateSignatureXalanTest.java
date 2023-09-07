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
package org.apache.xml.security.test.dom.signature;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.XPath2FilterContainer;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests that create signatures that require Xalan for the here() function
 */
class CreateSignatureXalanTest {

    private static final String CONFIG_FILE = "/config-xalan.xml";

    @BeforeAll
    public static void setup() {
        System.setProperty("org.apache.xml.security.resource.config", CONFIG_FILE);
        org.apache.xml.security.Init.init();
    }

    @AfterAll
    public static void cleanup() {
        System.clearProperty("org.apache.xml.security.resource.config");
    }

    @Test
    void testXFilter2Signature() throws Exception {
        Document doc = TestUtils.newDocument();
        doc.appendChild(doc.createComment(" Comment before "));
        Element root = doc.createElementNS("", "RootElement");

        doc.appendChild(root);
        root.appendChild(doc.createTextNode("Some simple text\n"));

        // Sign
        XMLSignature sig = new XMLSignature(doc, null, XMLSignature.ALGO_ID_SIGNATURE_DSA);
        root.appendChild(sig.getElement());

        Transforms transforms = new Transforms(doc);
        String filter = "here()/ancestor::ds.Signature/parent::node()/descendant-or-self::*";
        XPath2FilterContainer xpathC = XPath2FilterContainer.newInstanceIntersect(doc, filter);
        xpathC.setXPathNamespaceContext("dsig-xpath", Transforms.TRANSFORM_XPATH2FILTER);

        Element node = xpathC.getElement();
        transforms.addTransform(Transforms.TRANSFORM_XPATH2FILTER, node);
        sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);

        KeyStore ks = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(
            resolveFile("src/test/resources/org/apache/xml/security/samples/input/keystore.jks"))) {
            ks.load(fis, "xmlsecurity".toCharArray());
        }
        PrivateKey privateKey = (PrivateKey) ks.getKey("test", "xmlsecurity".toCharArray());

        sig.sign(privateKey);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        XMLUtils.outputDOMc14nWithComments(doc, bos);
        String signedDoc = new String(bos.toByteArray());

        // Now Verify
        try (InputStream is = new ByteArrayInputStream(signedDoc.getBytes())) {
            doc = XMLUtils.read(is, false);
        }

        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());

        String expression = "//ds:Signature[1]";
        Element sigElement = (Element) xpath.evaluate(expression, doc, XPathConstants.NODE);

        XMLSignature signature = new XMLSignature(sigElement, "");
        assertTrue(signature.checkSignatureValue(ks.getCertificate("test").getPublicKey()));
    }
}
