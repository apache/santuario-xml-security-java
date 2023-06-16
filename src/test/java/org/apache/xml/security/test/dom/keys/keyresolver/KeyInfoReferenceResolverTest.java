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
package org.apache.xml.security.test.dom.keys.keyresolver;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;

import org.apache.xml.security.Init;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;


class KeyInfoReferenceResolverTest {

    public KeyInfoReferenceResolverTest() throws Exception {
        if (!Init.isInitialized()) {
            Init.init();
        }
    }

    @Test
    void testRSAPublicKey() throws Exception {
        PublicKey rsaKeyControl = loadPublicKey("rsa-KeyInfoReference.key", "RSA");

        Document doc = loadXML("KeyInfoReference-RSA.xml");
        markKeyInfoIdAttrs(doc);

        Element referenceElement = doc.getElementById("theReference");
        assertNotNull(referenceElement);

        KeyInfo keyInfo = new KeyInfo(referenceElement, "");
        assertEquals(rsaKeyControl, keyInfo.getPublicKey());
    }

    @Test
    void testX509Certificate() throws Exception {
        X509Certificate certControl = loadCertificate("cert-KeyInfoReference.crt");

        Document doc = loadXML("KeyInfoReference-X509Certificate.xml");
        markKeyInfoIdAttrs(doc);

        Element referenceElement = doc.getElementById("theReference");
        assertNotNull(referenceElement);

        KeyInfo keyInfo = new KeyInfo(referenceElement, "");
        assertEquals(certControl, keyInfo.getX509Certificate());
        assertEquals(certControl.getPublicKey(), keyInfo.getPublicKey());
    }

    @Test
    void testWrongReferentType() throws Exception {
        Document doc = loadXML("KeyInfoReference-WrongReferentType.xml");
        markKeyInfoIdAttrs(doc);

        // Mark the ID-ness of the bogus element so can be resolved
        NodeList nl = doc.getElementsByTagNameNS("http://www.example.org/test", "KeyInfo");
        for (int i = 0; i < nl.getLength(); i++) {
            Element keyInfoElement = (Element) nl.item(i);
            keyInfoElement.setIdAttributeNS(null, Constants._ATT_ID, true);
        }

        Element referenceElement = doc.getElementById("theReference");
        assertNotNull(referenceElement);

        KeyInfo keyInfo = new KeyInfo(referenceElement, "");
        assertNull(keyInfo.getPublicKey());
    }

    @Test
    void testSameDocumentReferenceChain() throws Exception {
        Document doc = loadXML("KeyInfoReference-ReferenceChain.xml");
        markKeyInfoIdAttrs(doc);

        Element referenceElement = doc.getElementById("theReference");
        assertNotNull(referenceElement);

        KeyInfo keyInfo = new KeyInfo(referenceElement, "");
        // Chains of references are not supported at this time
        assertNull(keyInfo.getPublicKey());
    }

    @Test
    void testSameDocumentReferenceChainWithSecureValidation() throws Exception {
        Document doc = loadXML("KeyInfoReference-ReferenceChain.xml");
        markKeyInfoIdAttrs(doc);

        Element referenceElement = doc.getElementById("theReference");
        assertNotNull(referenceElement);

        KeyInfo keyInfo = new KeyInfo(referenceElement, "");
        keyInfo.setSecureValidation(true);
        // Chains of references are not supported at this time
        assertNull(keyInfo.getPublicKey());
    }

    @Test
    void testKeyInfoReferenceToRetrievalMethodNotAllowed() throws Exception {
        Document doc = loadXML("KeyInfoReference-RSA-RetrievalMethod.xml");
        markKeyInfoIdAttrs(doc);
        markEncodedKeyValueIdAttrs(doc);

        Element referenceElement = doc.getElementById("theReference");
        assertNotNull(referenceElement);

        KeyInfo keyInfo = new KeyInfo(referenceElement, "");
        assertNull(keyInfo.getPublicKey());
    }

    // Utility methods

    private Path getControlFilePath(String fileName) {
        return XmlSecTestEnvironment.resolvePath("src", "test", "resources", "org", "apache", "xml", "security",
            "keyresolver", fileName);
    }

    private Document loadXML(String fileName) throws Exception {
        return XMLUtils.read(getControlFilePath(fileName).toFile(), false);
    }

    private PublicKey loadPublicKey(String filePath, String algorithm) throws Exception {
        String fileData = Files.readString(getControlFilePath(filePath));
        byte[] keyBytes = XMLUtils.decode(fileData);
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return kf.generatePublic(keySpec);
    }

    private X509Certificate loadCertificate(String fileName) throws Exception {
        try (InputStream fis = Files.newInputStream(getControlFilePath(fileName))) {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certFactory.generateCertificate(fis);
        }
    }

    private void markKeyInfoIdAttrs(Document doc) {
        NodeList nl = doc.getElementsByTagNameNS(Constants.SignatureSpecNS, Constants._TAG_KEYINFO);
        for (int i = 0; i < nl.getLength(); i++) {
            Element keyInfoElement = (Element) nl.item(i);
            keyInfoElement.setIdAttributeNS(null, Constants._ATT_ID, true);
        }
    }

    private void markEncodedKeyValueIdAttrs(Document doc) {
        NodeList nl = doc.getElementsByTagNameNS(Constants.SignatureSpec11NS, Constants._TAG_DERENCODEDKEYVALUE);
        for (int i = 0; i < nl.getLength(); i++) {
            Element keyInfoElement = (Element) nl.item(i);
            keyInfoElement.setIdAttributeNS(null, Constants._ATT_ID, true);
        }
    }

}