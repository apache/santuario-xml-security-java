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


import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.Init;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Tests cases where signature algorithms are unknown.
 * <p>
 * The source documents are based on that created by the class <code>
 * org.apache.xml.security.samples.signature.CreateEnvelopingSignature</code>
 * </p>
 */
public class UnknownAlgoSignatureTest {

    protected static final String KEYSTORE_TYPE = "JKS";
    protected static final String KEYSTORE_FILE = "src/test/resources/org/apache/xml/security/samples/input/keystore.jks";
    protected static final String CERT_ALIAS = "test";
    protected static final String SIGNATURE_SOURCE_PATH = "src/test/resources/org/apache/xml/security/temp/signature";

    protected PublicKey publicKey;

    static {
        Init.init();
    }

    public UnknownAlgoSignatureTest() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        try (FileInputStream fis = new FileInputStream(resolveFile(KEYSTORE_FILE))) {
            keyStore.load(fis, null);
        }
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(CERT_ALIAS);
        publicKey = cert.getPublicKey();
    }

    @Test
    public void testGood() throws Exception {
        assertTrue(checkSignature("signature-good.xml"));
    }

    @Test
    public void testBadC14NAlgo() throws Exception {
        try {
            assertTrue(checkSignature("signature-bad-c14n-algo.xml"));
            fail("Exception not caught");
        } catch (XMLSignatureException e) {
            // succeed
        }
    }

    @Test
    public void testBadSigAlgo() throws Exception {
        try {
            assertTrue(checkSignature("signature-bad-sig-algo.xml"));
            fail("Exception not caught");
        } catch (XMLSignatureException e) {
            // succeed
        }
    }

    @Test
    public void testBadTransformAlgo() throws Exception {
        try {
            assertTrue(checkReferences("signature-bad-transform-algo.xml"));
            fail("Exception not caught");
        } catch (XMLSignatureException e) {
            // succeed
        }
    }

    protected boolean checkSignature(String fileName) throws Exception {
        XMLSignature signature = unmarshalXMLSignature(fileName);
        return signature.checkSignatureValue(publicKey);
    }

    protected boolean checkReferences(String fileName) throws Exception {
        XMLSignature signature = unmarshalXMLSignature(fileName);
        return signature.getSignedInfo().verify(false);
    }

    private XMLSignature unmarshalXMLSignature(String fileName) throws Exception {
        File file = XmlSecTestEnvironment.resolveFile(SIGNATURE_SOURCE_PATH, fileName);
        Document doc = getDocument(file);

        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());

        String expression = "//ds:Signature[1]";
        Element sigElement = (Element) xpath.evaluate(expression, doc, XPathConstants.NODE);
        return new XMLSignature(sigElement, file.toURI().toURL().toString());
    }

    public static Document getDocument(File file) throws Exception {
        return XMLUtils.read(file, false);
    }

}