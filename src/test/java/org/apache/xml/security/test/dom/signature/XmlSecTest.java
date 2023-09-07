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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.XPathContainer;
import org.apache.xml.security.utils.Constants;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * Tests creating and validating an XML Signature with an XPath Transform.
 * Tests bug #44617.
 *
 */
class XmlSecTest {

    @Test
    void testCheckXmlSignatureSoftwareStack() throws Exception {
        checkXmlSignatureSoftwareStack(false);
    }

    @Test
    void testCheckXmlSignatureSoftwareStackWithCert() throws Exception {
        checkXmlSignatureSoftwareStack(true);
    }

    private void checkXmlSignatureSoftwareStack(boolean cert) throws Exception {
        Init.init();
        Document testDocument = TestUtils.newDocument();

        Element rootElement =
            testDocument.createElementNS("urn:namespace", "tns:document");
        rootElement.setAttributeNS
            (Constants.NamespaceSpecNS, "xmlns:tns", "urn:namespace");
        testDocument.appendChild(rootElement);
        Element childElement =
            testDocument.createElementNS("urn:childnamespace", "t:child");
        childElement.setAttributeNS
            (Constants.NamespaceSpecNS, "xmlns:t", "urn:childnamespace");
        childElement.appendChild(testDocument.createTextNode("hello world"));
        rootElement.appendChild(childElement);

        PrivateKey privateKey;
        PublicKey publicKey = null;
        X509Certificate signingCert = null;
        if (cert) {
            KeyStore ks = XmlSecTestEnvironment.getTestKeyStore();
            signingCert = (X509Certificate) ks.getCertificate("mullan");
            publicKey = signingCert.getPublicKey();
            privateKey = (PrivateKey) ks.getKey("mullan", "changeit".toCharArray());
        } else {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
            kpg.initialize(1024);
            KeyPair keyPair = kpg.generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
        }

        XMLSignature signature =
            new XMLSignature(
                testDocument, "", XMLSignature.ALGO_ID_SIGNATURE_DSA,
                Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS
            );

        Element signatureElement = signature.getElement();
        rootElement.appendChild(signatureElement);

        Transforms transforms = new Transforms(testDocument);
        XPathContainer xpath = new XPathContainer(testDocument);
        xpath.setXPathNamespaceContext("ds", Constants.SignatureSpecNS);
        xpath.setXPath("not(ancestor-or-self::ds:Signature)");
        transforms.addTransform(Transforms.TRANSFORM_XPATH, xpath.getElementPlusReturns());
        transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
        signature.addDocument("", transforms, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1);

        if (cert) {
            signature.addKeyInfo(signingCert);
        } else {
            signature.addKeyInfo(publicKey);
        }

        Element nsElement = testDocument.createElementNS(null, "nsElement");
        nsElement.setAttributeNS(
            Constants.NamespaceSpecNS, "xmlns:ds", Constants.SignatureSpecNS
        );

        signature.sign(privateKey);

        XPathFactory xpf = XPathFactory.newInstance();
        XPath xPath = xpf.newXPath();
        xPath.setNamespaceContext(new DSNamespaceContext());

        String expression = "//ds:Signature[1]";
        Element sigElement =
            (Element) xPath.evaluate(expression, testDocument, XPathConstants.NODE);

        XMLSignature signatureToVerify = new XMLSignature(sigElement, "");

        boolean signResult = signatureToVerify.checkSignatureValue(publicKey);

        assertTrue(signResult);
    }

}