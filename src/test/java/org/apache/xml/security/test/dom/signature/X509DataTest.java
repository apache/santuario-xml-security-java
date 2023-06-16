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
import java.security.cert.X509Certificate;

import org.apache.xml.security.Init;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;


public class X509DataTest {

    KeyStore ks;

    @Test
    public void testAddX509SubjectName() throws Exception {
        Init.init();

        Document doc = TestUtils.newDocument();
        XMLSignature sig = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_DSA);

        doc.appendChild(sig.getElement());
        sig.addDocument("");

        //Add in the KeyInfo for the certificate that we used the private key of
        X509Certificate cert =getCertificate();
        sig.addKeyInfo(cert);
        sig.addKeyInfo(cert.getPublicKey());

        // Add these three lines
        org.apache.xml.security.keys.KeyInfo ki = sig.getKeyInfo();
        ki.itemX509Data(0).addSubjectName(cert.getSubjectX500Principal().getName());
        ki.itemX509Data(0).addIssuerSerial(cert.getIssuerX500Principal().getName(), cert.getSerialNumber());

        sig.sign(getPrivateKey());
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        XMLUtils.outputDOM(doc, os);
        XMLSignature newSig = getSignature(os.toByteArray());

        assertNotNull(newSig.getKeyInfo().itemX509Data(0));
        assertEquals(cert.getSubjectX500Principal().getName(),
                     newSig.getKeyInfo().itemX509Data(0).itemSubjectName(0).getSubjectName());
        assertEquals(cert.getIssuerX500Principal().getName(),
                     newSig.getKeyInfo().itemX509Data(0).itemIssuerSerial(0).getIssuerName());
    }

    private XMLSignature getSignature(byte[] s) throws Exception {

        Document doc = null;
        try (InputStream is = new ByteArrayInputStream(s)) {
            doc = XMLUtils.read(is, false);
        }
        Element el = (Element)doc.getFirstChild();
        return new XMLSignature(el, "");
    }

    private KeyStore getKeyStore() throws Exception {
        if (ks != null) {
            return ks;
        }
        String keystoreFile = "src/test/resources/org/apache/xml/security/samples/input/keystore.jks";
        ks = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(XmlSecTestEnvironment.resolveFile(keystoreFile))) {
            ks.load(fis, "xmlsecurity".toCharArray());
        }
        return ks;
    }

    private X509Certificate getCertificate() throws Exception {
        String certificateAlias = "test";
        X509Certificate cert =
            (X509Certificate) getKeyStore().getCertificate(certificateAlias);
        return cert;
    }

    private PrivateKey getPrivateKey() throws Exception {
        String privateKeyAlias = "test";
        String privateKeyPass = "xmlsecurity";
        PrivateKey privateKey =
            (PrivateKey) getKeyStore().getKey(privateKeyAlias, privateKeyPass.toCharArray());
        return privateKey;
    }

}