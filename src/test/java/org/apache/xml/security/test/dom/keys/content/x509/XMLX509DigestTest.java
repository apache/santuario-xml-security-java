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
package org.apache.xml.security.test.dom.keys.content.x509;

import java.io.File;
import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.apache.xml.security.Init;
import org.apache.xml.security.keys.content.x509.XMLX509Digest;
import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;


class XMLX509DigestTest {

    private static final String ALG_URI_CONTROL = "http://www.w3.org/2001/04/xmlenc#sha256";
    private static final String DIGEST_B64_CONTROL = "jToLQ/K7aaLHy/aXLFnjEfCwSQd9z0MrBOH6Ru/aJyY=";

    private final X509Certificate certControl;
    private final byte[] digestControl;

    public XMLX509DigestTest() throws Exception {
        certControl = loadCertificate("cert-X509Digest.crt");

        digestControl = XMLUtils.decode(DIGEST_B64_CONTROL);

        if (!Init.isInitialized()) {
            Init.init();
        }
    }

    @Test
    void testSchema() throws Exception {
        XMLX509Digest x509Digest = new XMLX509Digest(TestUtils.newDocument(), digestControl, ALG_URI_CONTROL);
        Element element = x509Digest.getElement();

        assertEquals("http://www.w3.org/2009/xmldsig11#", element.getNamespaceURI());
        assertEquals("X509Digest", element.getLocalName());
    }

    @Test
    void testDigestFromElement() throws Exception {
        Document doc = loadXML("X509Digest.xml");
        NodeList nl = doc.getElementsByTagNameNS(Constants.SignatureSpec11NS, Constants._TAG_X509DIGEST);
        Element element = (Element) nl.item(0);

        XMLX509Digest x509Digest = new XMLX509Digest(element, "");
        assertEquals(ALG_URI_CONTROL, x509Digest.getAlgorithm());
        assertArrayEquals(digestControl, x509Digest.getDigestBytes());
    }

    @Test
    void testDigestOnConstructionWithCert() throws Exception {
        XMLX509Digest x509Digest = new XMLX509Digest(TestUtils.newDocument(), certControl, ALG_URI_CONTROL);
        assertEquals(ALG_URI_CONTROL, x509Digest.getAlgorithm());
        assertArrayEquals(digestControl, x509Digest.getDigestBytes());
    }

    @Test
    void testDigestOnConstructionWithBytes() throws Exception {
        XMLX509Digest x509Digest = new XMLX509Digest(TestUtils.newDocument(), digestControl, ALG_URI_CONTROL);
        assertEquals(ALG_URI_CONTROL, x509Digest.getAlgorithm());
        assertArrayEquals(digestControl, x509Digest.getDigestBytes());
    }

    @Test
    void testGetDigestBytesFromCert() throws Exception {
        assertArrayEquals(digestControl, XMLX509Digest.getDigestBytesFromCert(certControl, ALG_URI_CONTROL));
    }


    // Utility methods

    private File getControlFilePath(String fileName) {
        return XmlSecTestEnvironment.resolveFile("src", "test", "resources", "org", "apache", "xml", "security", "keys",
            "content", "x509", fileName);
    }

    private Document loadXML(String fileName) throws Exception {
        return XMLUtils.read(getControlFilePath(fileName), false);
    }

    private X509Certificate loadCertificate(String fileName) throws Exception {
        try (FileInputStream fis = new FileInputStream(getControlFilePath(fileName))) {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certFactory.generateCertificate(fis);
        }
    }

}