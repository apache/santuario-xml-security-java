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
package org.apache.xml.security.test.dom.utils;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.keys.keyresolver.KeyResolver;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.implementations.TransformXPath;
import org.apache.xml.security.transforms.params.XPathContainer;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.apache.xml.security.utils.I18n;
import org.apache.xml.security.utils.JDKXPathFactory;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test the JDKXPathFactory by adding a custom transform that hard-wires the use of JDKXPathFactory, instead of
 * checking to see whether Xalan is on the classpath or not
 */
public class JDKXPathFactoryTest {

    static org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(JDKXPathFactoryTest.class);

    private KeyPair kp;

    public JDKXPathFactoryTest() throws Exception {
        // org.apache.xml.security.Init.init();
        // Instead of calling Init.init(), instead initialize the library manually
        I18n.init("en", "US");
        ElementProxy.registerDefaultPrefixes();
        SignatureAlgorithm.registerDefaultAlgorithms();
        JCEMapper.registerDefaultAlgorithms();
        Canonicalizer.registerDefaultAlgorithms();
        ResourceResolver.registerDefaultResolvers();
        KeyResolver.registerDefaultResolvers();

        // Manually register TransformJDKXPath
        Transform.register(Transforms.TRANSFORM_XPATH, TransformJDKXPath.class);

        kp = KeyPairGenerator.getInstance("RSA").genKeyPair();
    }

    @org.junit.jupiter.api.Test
    public void testXPathSignature() throws Exception {
        Document doc = TestUtils.newDocument();
        doc.appendChild(doc.createComment(" Comment before "));
        Element root = doc.createElementNS("", "RootElement");

        doc.appendChild(root);
        root.appendChild(doc.createTextNode("Some simple text\n"));

        // Sign
        XMLSignature sig =
                new XMLSignature(doc, null, XMLSignature.ALGO_ID_SIGNATURE_RSA);
        root.appendChild(sig.getElement());

        ObjectContainer object = new ObjectContainer(doc);
        object.setId("object-1");
        object.setMimeType("text/plain");
        object.setEncoding("http://www.w3.org/2000/09/xmldsig#base64");
        object.appendChild(doc.createTextNode("SSBhbSB0aGUgdGV4dC4="));
        sig.appendObject(object);

        Transforms transforms = new Transforms(doc);
        XPathContainer xpathC = new XPathContainer(doc);
        xpathC.setXPath("ancestor-or-self::dsig-xpath:Object");
        xpathC.setXPathNamespaceContext("dsig-xpath", Transforms.TRANSFORM_XPATH);

        Element node = xpathC.getElement();
        transforms.addTransform(Transforms.TRANSFORM_XPATH, node);
        sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);

        sig.sign(kp.getPrivate());

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
        Element sigElement =
                (Element) xpath.evaluate(expression, doc, XPathConstants.NODE);

        XMLSignature signature = new XMLSignature(sigElement, "");
        assertTrue(signature.checkSignatureValue(kp.getPublic()));
    }

    public static class TransformJDKXPath extends TransformXPath {
        @Override
        protected org.apache.xml.security.utils.XPathFactory getXPathFactory() {
            return new JDKXPathFactory();
        }
    }

}