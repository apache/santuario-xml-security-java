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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.SignatureProperties;
import org.apache.xml.security.signature.SignatureProperty;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.XPathContainer;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Tests that create signatures.
 *
 */
public class CreateSignatureTest {

    private final KeyPair kp;

    public CreateSignatureTest() throws Exception {
        org.apache.xml.security.Init.init();
        kp = KeyPairGenerator.getInstance("RSA").genKeyPair();
    }

    /**
     * Test for bug 36044 - Canonicalizing an empty node-set throws an
     * ArrayIndexOutOfBoundsException.
     */
    @Test
    public void testEmptyNodeSet() throws Exception {
        Document doc = TestUtils.newDocument();
        Element envelope = doc.createElementNS("http://www.usps.gov/", "Envelope");
        envelope.appendChild(doc.createTextNode("\n"));
        doc.appendChild(envelope);

        XMLSignature sig =
            new XMLSignature(doc, null, XMLSignature.ALGO_ID_SIGNATURE_DSA);
        envelope.appendChild(sig.getElement());

        ObjectContainer object1 = new ObjectContainer(doc);
        object1.setId("object-1");
        object1.setMimeType("text/plain");
        sig.appendObject(object1);

        ObjectContainer object2 = new ObjectContainer(doc);

        object2.setId("object-2");
        object2.setMimeType("text/plain");
        object2.setEncoding("http://www.w3.org/2000/09/xmldsig#base64");
        object2.appendChild(doc.createTextNode("SSBhbSB0aGUgdGV4dC4="));
        sig.appendObject(object2);

        Transforms transforms = new Transforms(doc);
        XPathContainer xpathC = new XPathContainer(doc);

        xpathC.setXPath("self::text()");
        transforms.addTransform(Transforms.TRANSFORM_XPATH, xpathC.getElementPlusReturns());
        sig.addDocument(
            "#object-1", transforms, Constants.ALGO_ID_DIGEST_SHA1, null,
            "http://www.w3.org/2000/09/xmldsig#Object"
        );

        KeyStore ks = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(
            resolveFile("src/test/resources/org/apache/xml/security/samples/input/keystore.jks"))) {
            ks.load(fis, "xmlsecurity".toCharArray());
        }
        PrivateKey privateKey = (PrivateKey) ks.getKey("test", "xmlsecurity".toCharArray());

        sig.sign(privateKey);
    }

    @Test
    public void testOne() throws Exception {
        doVerify(doSign());
        doVerify(doSign());
    }

    @Test
    public void testTwo() throws Exception {
        doSignWithCert();
    }

    @Test
    public void testWithNSPrefixDisabled() throws Exception {
        String prefix = ElementProxy.getDefaultPrefix(Constants.SignatureSpecNS);
        try {
            ElementProxy.setDefaultPrefix(Constants.SignatureSpecNS, "");
            doSign();
            ElementProxy.setDefaultPrefix(Constants.SignatureSpecNS, prefix);
        } catch (Exception e) {
            ElementProxy.setDefaultPrefix(Constants.SignatureSpecNS, prefix);
            throw e;
        }
    }

    @Test
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

    @Test
    public void testCanonicalizedOctetStream() throws Exception {
        String signedXML = doSign();

        Document doc = null;
        try (InputStream is = new ByteArrayInputStream(signedXML.getBytes())) {
            doc = XMLUtils.read(is, false);
        }

        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());

        String expression = "//ds:Signature[1]";
        Element sigElement =
            (Element) xpath.evaluate(expression, doc, XPathConstants.NODE);

        XMLSignature signature = new XMLSignature(sigElement, "");
        KeyInfo ki = signature.getKeyInfo();

        if (ki == null) {
            throw new RuntimeException("No keyinfo");
        }
        PublicKey pk = signature.getKeyInfo().getPublicKey();

        if (pk == null) {
            throw new RuntimeException("No public key");
        }

        SignedInfo si = signature.getSignedInfo();
        SignatureAlgorithm sa = si.getSignatureAlgorithm();
        sa.initVerify(pk);

        byte[] sigBytes = signature.getSignatureValue();

        byte[] canonicalizedBytes = si.getCanonicalizedOctetStream();
        sa.update(canonicalizedBytes, 0, canonicalizedBytes.length);

        assertTrue(sa.verify(sigBytes));
        assertTrue(si.verify(false));
    }

    @Test
    public void testSHA256Digest() throws Exception {
        PrivateKey privateKey = kp.getPrivate();
        Document doc = TestUtils.newDocument();
        doc.appendChild(doc.createComment(" Comment before "));
        Element root = doc.createElementNS("", "RootElement");

        doc.appendChild(root);
        root.appendChild(doc.createTextNode("Some simple text\n"));

        Element canonElem =
            XMLUtils.createElementInSignatureSpace(doc, Constants._TAG_CANONICALIZATIONMETHOD);
        canonElem.setAttributeNS(
            null, Constants._ATT_ALGORITHM, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS
        );

        SignatureAlgorithm signatureAlgorithm =
            new SignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        XMLSignature sig =
            new XMLSignature(doc, null, signatureAlgorithm.getElement(), canonElem);

        root.appendChild(sig.getElement());
        doc.appendChild(doc.createComment(" Comment after "));
        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
        sig.addDocument("", transforms, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);

        sig.addKeyInfo(kp.getPublic());
        sig.sign(privateKey);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        XMLUtils.outputDOMc14nWithComments(doc, bos);
        String signedContent = new String(bos.toByteArray());

        doVerify(signedContent);
    }

    @Test
    public void testSignatureProperties() throws Exception {
        PrivateKey privateKey = kp.getPrivate();
        Document doc = TestUtils.newDocument();
        Element root = doc.createElementNS("", "RootElement");

        doc.appendChild(root);
        root.appendChild(doc.createTextNode("Some simple text\n"));

        Element canonElem =
            XMLUtils.createElementInSignatureSpace(doc, Constants._TAG_CANONICALIZATIONMETHOD);
        canonElem.setAttributeNS(
            null, Constants._ATT_ALGORITHM, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS
        );

        SignatureAlgorithm signatureAlgorithm =
            new SignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);
        XMLSignature sig =
            new XMLSignature(doc, null, signatureAlgorithm.getElement(), canonElem);
        String id = "12345";
        sig.setId(id);

        ObjectContainer object = new ObjectContainer(doc);
        SignatureProperties signatureProperties = new SignatureProperties(doc);
        String sigPropertiesId = "54321";
        signatureProperties.setId(sigPropertiesId);
        SignatureProperty signatureProperty = new SignatureProperty(doc, "#" + id);
        signatureProperties.addSignatureProperty(signatureProperty);
        object.appendChild(signatureProperties.getElement());
        signatureProperties.getElement().setIdAttributeNS(null, "Id", true);
        sig.appendObject(object);
        sig.addDocument("#" + sigPropertiesId);

        root.appendChild(sig.getElement());
        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
        sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);

        sig.addKeyInfo(kp.getPublic());
        sig.sign(privateKey);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        XMLUtils.outputDOMc14nWithComments(doc, bos);
        String signedContent = new String(bos.toByteArray());
        doVerify(signedContent, 1);
    }

    @Test
    public void testAddDuplicateKeyInfo() throws Exception {
        PrivateKey privateKey = kp.getPrivate();
        Document doc = TestUtils.newDocument();
        Element root = doc.createElementNS("", "RootElement");

        doc.appendChild(root);
        root.appendChild(doc.createTextNode("Some simple text\n"));

        Element canonElem =
            XMLUtils.createElementInSignatureSpace(doc, Constants._TAG_CANONICALIZATIONMETHOD);
        canonElem.setAttributeNS(
            null, Constants._ATT_ALGORITHM, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS
        );

        SignatureAlgorithm signatureAlgorithm =
            new SignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);
        XMLSignature sig =
            new XMLSignature(doc, null, signatureAlgorithm.getElement(), canonElem);
        String id = "12345";
        sig.setId(id);

        root.appendChild(sig.getElement());
        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
        sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);

        sig.addKeyInfo(kp.getPublic());
        sig.sign(privateKey);

        // Add a duplicate (empty) KeyInfo element
        KeyInfo keyInfo = new KeyInfo(doc);
        sig.getElement().appendChild(keyInfo.getElement());

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        XMLUtils.outputDOMc14nWithComments(doc, bos);
        String signedContent = new String(bos.toByteArray());
        try {
            doVerify(signedContent);
            fail("Failure expected on a duplicate KeyInfo element");
        } catch (XMLSignatureException ex) {
            // expected
        }
    }

    @Test
    public void testWrongSignatureName() throws Exception {
        PrivateKey privateKey = kp.getPrivate();
        Document doc = TestUtils.newDocument();
        Element root = doc.createElementNS("", "RootElement");

        doc.appendChild(root);
        root.appendChild(doc.createTextNode("Some simple text\n"));

        Element canonElem =
            XMLUtils.createElementInSignatureSpace(doc, Constants._TAG_CANONICALIZATIONMETHOD);
        canonElem.setAttributeNS(
            null, Constants._ATT_ALGORITHM, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS
        );

        SignatureAlgorithm signatureAlgorithm =
            new SignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);
        XMLSignature sig =
            new XMLSignature(doc, null, signatureAlgorithm.getElement(), canonElem);
        String id = "12345";
        sig.setId(id);

        ObjectContainer object = new ObjectContainer(doc);
        SignatureProperties signatureProperties = new SignatureProperties(doc);
        String sigPropertiesId = "54321";
        signatureProperties.setId(sigPropertiesId);
        SignatureProperty signatureProperty = new SignatureProperty(doc, "#" + id);
        signatureProperties.addSignatureProperty(signatureProperty);
        object.appendChild(signatureProperties.getElement());
        signatureProperties.getElement().setIdAttributeNS(null, "Id", true);
        sig.appendObject(object);
        sig.addDocument("#" + sigPropertiesId);

        root.appendChild(sig.getElement());

        sig.addKeyInfo(kp.getPublic());
        sig.sign(privateKey);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        XMLUtils.outputDOMc14nWithComments(doc, bos);
        String signedContent = new String(bos.toByteArray());
        // Now change the Signature Element to be "SomeSignature" instead
        signedContent = signedContent.replaceAll("ds:Signature ", "ds:SomeSignature ");
        signedContent = signedContent.replaceAll("</ds:Signature>", "</ds:SomeSignature>");

        // Verify the signature
        Document doc2 = null;
        try (InputStream is = new ByteArrayInputStream(signedContent.getBytes())) {
            doc2 = XMLUtils.read(is, false);
        }

        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());

        String expression = "//ds:SomeSignature[1]";
        Element sigElement =
            (Element) xpath.evaluate(expression, doc2, XPathConstants.NODE);

        try {
            new XMLSignature(sigElement, "");
            fail("Failure expected on an incorrect Signature element name");
        } catch (XMLSignatureException ex) {
            // expected
        }
    }

    private String doSign() throws Exception {
        PrivateKey privateKey = kp.getPrivate();
        Document doc = TestUtils.newDocument();
        doc.appendChild(doc.createComment(" Comment before "));
        Element root = doc.createElementNS("", "RootElement");

        doc.appendChild(root);
        root.appendChild(doc.createTextNode("Some simple text\n"));

        Element canonElem =
            XMLUtils.createElementInSignatureSpace(doc, Constants._TAG_CANONICALIZATIONMETHOD);
        canonElem.setAttributeNS(
            null, Constants._ATT_ALGORITHM, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS
        );

        SignatureAlgorithm signatureAlgorithm =
            new SignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);
        XMLSignature sig =
            new XMLSignature(doc, null, signatureAlgorithm.getElement(), canonElem);

        root.appendChild(sig.getElement());
        doc.appendChild(doc.createComment(" Comment after "));
        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
        sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);

        sig.addKeyInfo(kp.getPublic());
        sig.sign(privateKey);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        XMLUtils.outputDOMc14nWithComments(doc, bos);
        return new String(bos.toByteArray());
    }

    private String doSignWithCert() throws Exception {
        KeyStore ks = XmlSecTestEnvironment.getTestKeyStore();
        PrivateKey privateKey = (PrivateKey) ks.getKey("mullan", "changeit".toCharArray());
        Document doc = TestUtils.newDocument();
        X509Certificate signingCert = (X509Certificate) ks.getCertificate("mullan");
        doc.appendChild(doc.createComment(" Comment before "));
        Element root = doc.createElementNS("", "RootElement");

        doc.appendChild(root);
        root.appendChild(doc.createTextNode("Some simple text\n"));

        Element canonElem =
            XMLUtils.createElementInSignatureSpace(doc, Constants._TAG_CANONICALIZATIONMETHOD);
        canonElem.setAttributeNS(
            null, Constants._ATT_ALGORITHM, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS
        );

        SignatureAlgorithm signatureAlgorithm =
            new SignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_DSA);
        XMLSignature sig =
            new XMLSignature(doc, null, signatureAlgorithm.getElement(), canonElem);

        root.appendChild(sig.getElement());
        doc.appendChild(doc.createComment(" Comment after "));
        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
        sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);

        sig.addKeyInfo(signingCert);
        sig.sign(privateKey);
        X509Certificate cert = sig.getKeyInfo().getX509Certificate();
        sig.checkSignatureValue(cert.getPublicKey());
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        XMLUtils.outputDOMc14nWithComments(doc, bos);
        return new String(bos.toByteArray());
    }

    private void doVerify(String signedXML) throws Exception {
        doVerify(signedXML, 0);
    }

    private void doVerify(String signedXML, int expectedObjectCount) throws Exception {
        Document doc = null;
        try (InputStream is = new ByteArrayInputStream(signedXML.getBytes())) {
            doc = XMLUtils.read(is, false);
        }

        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());

        String expression = "//ds:Signature[1]";
        Element sigElement =
            (Element) xpath.evaluate(expression, doc, XPathConstants.NODE);

        XMLSignature signature = new XMLSignature(sigElement, "");
        KeyInfo ki = signature.getKeyInfo();

        if (ki == null) {
            throw new RuntimeException("No keyinfo");
        }
        PublicKey pk = signature.getKeyInfo().getPublicKey();

        if (pk == null) {
            throw new RuntimeException("No public key");
        }
        assertTrue(signature.checkSignatureValue(pk));

        assertEquals(expectedObjectCount, signature.getObjectLength());
        if (expectedObjectCount > 0) {
            for (int i = 0; i < expectedObjectCount; i++) {
                assertNotNull(signature.getObjectItem(i));
            }
        }
    }

}