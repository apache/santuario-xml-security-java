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
package org.apache.xml.security.test.dom.secure_val;


import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Enumeration;

import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.test.dom.interop.InteropTestBase;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * This is a test for a forbidden number of references when secure validation is enabled.
 */
public class ForbiddenRefCountTest extends InteropTestBase {

    private static final String BASEDIR =
        System.getProperty("basedir") == null ? "./": System.getProperty("basedir");
    public static final String KEYSTORE_DIRECTORY = BASEDIR + "/src/test/resources/";
    public static final String KEYSTORE_PASSWORD_STRING = "changeit";
    public static final char[] KEYSTORE_PASSWORD = KEYSTORE_PASSWORD_STRING.toCharArray();

    static org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(ForbiddenRefCountTest.class);

    static {
        org.apache.xml.security.Init.init();
    }

    public ForbiddenRefCountTest() {
        super();
    }

    @org.junit.jupiter.api.Test
    public void testReferenceCount() throws Exception {
        Document doc = getOriginalDocument();
        signDocument(doc, 31);
        assertTrue(verifySignature(doc, false));

        try {
            verifySignature(doc, true);
            fail("Failure expected when secure validation is enabled");
        } catch (XMLSecurityException ex) {
            assertTrue(ex.getMessage().contains("references are contained in the Manifest"));
        }
    }

    private Document getOriginalDocument() throws ParserConfigurationException {
        Document doc = TestUtils.newDocument();

        Element rootElement = doc.createElementNS("http://ns.example.org/", "root");
        rootElement.appendChild(doc.createTextNode("Hello World!"));
        doc.appendChild(rootElement);

        return doc;
    }

    private void signDocument(Document doc, int refCount) throws Exception {
        XMLSignature sig = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_DSA);
        Element root = doc.getDocumentElement();
        root.appendChild(sig.getElement());

        for (int i = 0; i < refCount; i++) {
            Transforms transforms = new Transforms(doc);
            transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
            transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
            sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);
        }

        sig.addKeyInfo(getPublicKey());
        sig.sign(getPrivateKey());
    }

    private boolean verifySignature(Document doc, boolean secValidation) throws XMLSignatureException, XMLSecurityException {
        Element sigElement =
            (Element) doc.getElementsByTagNameNS(Constants.SignatureSpecNS,
                                                 Constants._TAG_SIGNATURE).item(0);
        XMLSignature signature = new XMLSignature(sigElement, null, secValidation);
        return signature.checkSignatureValue(signature.getKeyInfo().getPublicKey());
    }

    private KeyStore getKeyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        InputStream ksis = new FileInputStream(KEYSTORE_DIRECTORY + "test.jks");
        ks.load(ksis, KEYSTORE_PASSWORD);
        ksis.close();
        return ks;
    }

    private PublicKey getPublicKey() throws Exception {
        KeyStore keyStore = getKeyStore();
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                return keyStore.getCertificate(alias).getPublicKey();
            }
        }
        return null;
    }

    private PrivateKey getPrivateKey() throws Exception {
        KeyStore keyStore = getKeyStore();
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                return (PrivateKey) keyStore.getKey(alias, KEYSTORE_PASSWORD);
            }
        }
        return null;
    }

}