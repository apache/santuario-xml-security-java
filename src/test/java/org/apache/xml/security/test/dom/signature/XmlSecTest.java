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
public class XmlSecTest {

    @Test
    public void testCheckXmlSignatureSoftwareStack() throws Exception {
        checkXmlSignatureSoftwareStack(false);
    }

    @Test
    public void testCheckXmlSignatureSoftwareStackWithCert() throws Exception {
        checkXmlSignatureSoftwareStack(true);
    }

    private void checkXmlSignatureSoftwareStack(boolean cert) throws Exception {
        Init.init();
        final Document testDocument = TestUtils.newDocument();

        final Element rootElement =
            testDocument.createElementNS("urn:namespace", "tns:document");
        rootElement.setAttributeNS
            (Constants.NamespaceSpecNS, "xmlns:tns", "urn:namespace");
        testDocument.appendChild(rootElement);
        final Element childElement =
            testDocument.createElementNS("urn:childnamespace", "t:child");
        childElement.setAttributeNS
            (Constants.NamespaceSpecNS, "xmlns:t", "urn:childnamespace");
        childElement.appendChild(testDocument.createTextNode("hello world"));
        rootElement.appendChild(childElement);

        PrivateKey privateKey;
        PublicKey publicKey = null;
        X509Certificate signingCert = null;
        if (cert) {
            final KeyStore ks = XmlSecTestEnvironment.getTestKeyStore();
            signingCert = (X509Certificate) ks.getCertificate("mullan");
            publicKey = signingCert.getPublicKey();
            privateKey = (PrivateKey) ks.getKey("mullan", "changeit".toCharArray());
        } else {
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
            kpg.initialize(1024);
            final KeyPair keyPair = kpg.generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
        }

        final XMLSignature signature =
            new XMLSignature(
                testDocument, "", XMLSignature.ALGO_ID_SIGNATURE_DSA,
                Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS
            );

        final Element signatureElement = signature.getElement();
        rootElement.appendChild(signatureElement);

        final Transforms transforms = new Transforms(testDocument);
        final XPathContainer xpath = new XPathContainer(testDocument);
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

        final Element nsElement = testDocument.createElementNS(null, "nsElement");
        nsElement.setAttributeNS(
            Constants.NamespaceSpecNS, "xmlns:ds", Constants.SignatureSpecNS
        );

        signature.sign(privateKey);

        final XPathFactory xpf = XPathFactory.newInstance();
        final XPath xPath = xpf.newXPath();
        xPath.setNamespaceContext(new DSNamespaceContext());

        final String expression = "//ds:Signature[1]";
        final Element sigElement =
            (Element) xPath.evaluate(expression, testDocument, XPathConstants.NODE);

        final XMLSignature signatureToVerify = new XMLSignature(sigElement, "");

        final boolean signResult = signatureToVerify.checkSignatureValue(publicKey);

        assertTrue(signResult);
    }

}