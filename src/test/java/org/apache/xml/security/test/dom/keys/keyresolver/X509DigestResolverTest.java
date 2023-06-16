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

import java.io.File;
import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.apache.xml.security.Init;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.storage.StorageResolver;
import org.apache.xml.security.keys.storage.implementations.SingleCertificateResolver;
import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;


public class X509DigestResolverTest {

    private final X509Certificate certControl;

    private final StorageResolver storageResolver;

    public X509DigestResolverTest() throws Exception {
        certControl = loadCertificate("cert-X509Digest.crt");

        storageResolver = new StorageResolver(new SingleCertificateResolver(certControl));

        if (!Init.isInitialized()) {
            Init.init();
        }
    }

    @Test
    public void testDigest() throws Exception {
        Document doc = loadXML("X509Digest.xml");
        Element element = doc.getDocumentElement();

        KeyInfo keyInfo = new KeyInfo(element, "");

        assertNull(keyInfo.getX509Certificate());
        assertNull(keyInfo.getPublicKey());

        keyInfo.addStorageResolver(storageResolver);

        assertEquals(certControl, keyInfo.getX509Certificate());
        assertEquals(certControl.getPublicKey(), keyInfo.getPublicKey());
    }


    // Utility methods

    private File getControlFilePath(String fileName) {
        return XmlSecTestEnvironment.resolveFile("src", "test", "resources", "org", "apache", "xml",
            "security", "keys", "content", "x509", fileName);
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