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
package org.apache.xml.security.test.javax.xml.crypto.dsig;

import java.security.Key;
import java.security.Security;
import java.util.Collections;

import javax.xml.crypto.KeySelector;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;

import org.apache.xml.security.test.javax.xml.crypto.KeySelectors;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * Test signing using all available digest methods
 */
class SignatureDigestMethodTest {

    private final KeySelector kvks;
    private final CanonicalizationMethod withoutComments;
    private final DigestMethod sha1, sha224, sha256, sha384, sha512, ripemd160,
                whirlpool, sha3_224, sha3_256, sha3_384, sha3_512;
    private final SignatureMethod rsaSha1;
    private final KeyInfo rsaki;
    private final XMLSignatureFactory fac;
    private boolean bcInstalled;

    static {
        Security.insertProviderAt
            (new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    public SignatureDigestMethodTest() throws Exception {

        // create common objects
        fac = XMLSignatureFactory.getInstance("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
        KeyInfoFactory kifac = fac.getKeyInfoFactory();
        withoutComments = fac.newCanonicalizationMethod
            (CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null);

        // Digest Methods
        sha1 = fac.newDigestMethod(DigestMethod.SHA1, null);
        sha224 = fac.newDigestMethod("http://www.w3.org/2001/04/xmldsig-more#sha224", null);
        sha256 = fac.newDigestMethod(DigestMethod.SHA256, null);
        sha384 = fac.newDigestMethod("http://www.w3.org/2001/04/xmldsig-more#sha384", null);
        sha512 = fac.newDigestMethod(DigestMethod.SHA512, null);
        ripemd160 = fac.newDigestMethod(DigestMethod.RIPEMD160, null);
        whirlpool = fac.newDigestMethod("http://www.w3.org/2007/05/xmldsig-more#whirlpool", null);
        sha3_224 = fac.newDigestMethod("http://www.w3.org/2007/05/xmldsig-more#sha3-224", null);
        sha3_256 = fac.newDigestMethod("http://www.w3.org/2007/05/xmldsig-more#sha3-256", null);
        sha3_384 = fac.newDigestMethod("http://www.w3.org/2007/05/xmldsig-more#sha3-384", null);
        sha3_512 = fac.newDigestMethod("http://www.w3.org/2007/05/xmldsig-more#sha3-512", null);

        rsaSha1 = fac.newSignatureMethod
            ("http://www.w3.org/2000/09/xmldsig#rsa-sha1", null);

        rsaki = kifac.newKeyInfo(Collections.singletonList
                                 (kifac.newKeyValue(
                                  TestUtils.getPublicKey("RSA"))));

        kvks = new KeySelectors.KeyValueKeySelector();
    }

    @Test
    void testSHA1() throws Exception {
        test_create_signature_enveloping(rsaSha1, sha1, rsaki,
                                         TestUtils.getPrivateKey("RSA"), kvks);
    }

    @Test
    void testSHA224() throws Exception {
        test_create_signature_enveloping(rsaSha1, sha224, rsaki,
                                         TestUtils.getPrivateKey("RSA"), kvks);
    }

    @Test
    void testSHA256() throws Exception {
        test_create_signature_enveloping(rsaSha1, sha256, rsaki,
                                         TestUtils.getPrivateKey("RSA"), kvks);
    }

    @Test
    void testSHA384() throws Exception {
        test_create_signature_enveloping(rsaSha1, sha384, rsaki,
                                         TestUtils.getPrivateKey("RSA"), kvks);
    }

    @Test
    void testSHA512() throws Exception {
        test_create_signature_enveloping(rsaSha1, sha512, rsaki,
                                         TestUtils.getPrivateKey("RSA"), kvks);
    }

    @Test
    void testRIPEMD160() throws Exception {
        Assumptions.assumeTrue(bcInstalled);
        test_create_signature_enveloping(rsaSha1, ripemd160, rsaki,
                                         TestUtils.getPrivateKey("RSA"), kvks);
    }

    @Test
    void testWHIRLPOOL() throws Exception {
        Assumptions.assumeTrue(bcInstalled);
        test_create_signature_enveloping(rsaSha1, whirlpool, rsaki,
                                         TestUtils.getPrivateKey("RSA"), kvks);
    }

    @Test
    void testSHA3_224() throws Exception {
        Assumptions.assumeTrue(bcInstalled);
        test_create_signature_enveloping(rsaSha1, sha3_224, rsaki,
                                         TestUtils.getPrivateKey("RSA"), kvks);
    }

    @Test
    void testSHA3_256() throws Exception {
        Assumptions.assumeTrue(bcInstalled);
        test_create_signature_enveloping(rsaSha1, sha3_256, rsaki,
                                         TestUtils.getPrivateKey("RSA"), kvks);
    }

    @Test
    void testSHA3_384() throws Exception {
        Assumptions.assumeTrue(bcInstalled);
        test_create_signature_enveloping(rsaSha1, sha3_384, rsaki,
                                         TestUtils.getPrivateKey("RSA"), kvks);
    }

    @Test
    void testSHA3_512() throws Exception {
        Assumptions.assumeTrue(bcInstalled);
        test_create_signature_enveloping(rsaSha1, sha3_512, rsaki,
                                         TestUtils.getPrivateKey("RSA"), kvks);
    }

    private void test_create_signature_enveloping(
        SignatureMethod sm, DigestMethod dm, KeyInfo ki, Key signingKey, KeySelector ks
    ) throws Exception {

        // create reference
        Reference ref = fac.newReference("#DSig.Object_1", dm, null,
                                         XMLObject.TYPE, null);

        // create SignedInfo
        SignedInfo si = fac.newSignedInfo(withoutComments, sm,
                                          Collections.singletonList(ref));

        Document doc = TestUtils.newDocument();
        // create Objects
        Element webElem = doc.createElementNS(null, "Web");
        Text text = doc.createTextNode("up up and away");
        webElem.appendChild(text);
        XMLObject obj = fac.newXMLObject(Collections.singletonList
                                         (new DOMStructure(webElem)), "DSig.Object_1", "text/xml", null);

        // create XMLSignature
        XMLSignature sig = fac.newXMLSignature
        (si, ki, Collections.singletonList(obj), null, null);

        DOMSignContext dsc = new DOMSignContext(signingKey, doc);
        dsc.setDefaultNamespacePrefix("dsig");

        sig.sign(dsc);
        TestUtils.validateSecurityOrEncryptionElement(doc.getDocumentElement());

        // XMLUtils.outputDOM(doc.getDocumentElement(), System.out);

        DOMValidateContext dvc = new DOMValidateContext
        (ks, doc.getDocumentElement());
        XMLSignature sig2 = fac.unmarshalXMLSignature(dvc);

        assertEquals(sig, sig2);
        assertTrue(sig2.validate(dvc));
    }

}