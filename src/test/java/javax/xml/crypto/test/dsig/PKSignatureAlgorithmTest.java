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
package javax.xml.crypto.test.dsig;

import java.lang.reflect.Constructor;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
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
import javax.xml.crypto.test.KeySelectors;

import org.apache.jcp.xml.dsig.internal.dom.RSAPSSParameterSpec;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * Test signing using all available PublicKey signing algorithms
 */
public class PKSignatureAlgorithmTest {

    private KeySelector kvks;
    private CanonicalizationMethod withoutComments;
    private DigestMethod sha1;
    private SignatureMethod rsaSha1, rsaSha224, rsaSha256, rsaSha384, rsaSha512, rsaRipemd160;
    private SignatureMethod rsaSha1Mgf1, rsaSha224Mgf1, rsaSha256Mgf1, rsaSha384Mgf1, rsaSha512Mgf1, rsaPss, rsaPssSha512;
    private SignatureMethod ecdsaSha1, ecdsaSha224, ecdsaSha256, ecdsaSha384, ecdsaSha512, ecdsaRipemd160;
    private XMLSignatureFactory fac;
    private KeyPair rsaKeyPair, ecKeyPair;
    private KeyInfo rsaki, ecki;
    private boolean ecAlgParamsSupport = true;
    private static boolean bcInstalled;

    static {
        Security.insertProviderAt
            (new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    @BeforeAll
    public static void setup() throws Exception {
        //
        // If the BouncyCastle provider is not installed, then try to load it
        // via reflection.
        //
        if (Security.getProvider("BC") == null) {
            Constructor<?> cons = null;
            try {
                Class<?> c = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
                cons = c.getConstructor(new Class[] {});
            } catch (Exception e) {
                //ignore
            }
            if (cons != null) {
                Provider provider = (Provider)cons.newInstance();
                Security.insertProviderAt(provider, 2);
                bcInstalled = true;
            }
        }
    }

    public PKSignatureAlgorithmTest() throws Exception {

        // check if EC AlgorithmParameters is supported - this is needed
        // for marshalling ECKeyValue elements
        try {
            AlgorithmParameters.getInstance("EC");
        } catch (NoSuchAlgorithmException nsae) {
            ecAlgParamsSupport = false;
        }

        // create common objects
        fac = XMLSignatureFactory.getInstance("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
        withoutComments = fac.newCanonicalizationMethod
            (CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null);

        // Digest Methods
        sha1 = fac.newDigestMethod(DigestMethod.SHA1, null);

        rsaSha1 = fac.newSignatureMethod("http://www.w3.org/2000/09/xmldsig#rsa-sha1", null);
        rsaSha224 = fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha224", null);
        rsaSha256 = fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null);
        rsaSha384 = fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", null);
        rsaSha512 = fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", null);
        rsaRipemd160 = fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160", null);

        rsaSha1Mgf1 = fac.newSignatureMethod("http://www.w3.org/2007/05/xmldsig-more#sha1-rsa-MGF1", null);
        rsaSha224Mgf1 = fac.newSignatureMethod("http://www.w3.org/2007/05/xmldsig-more#sha224-rsa-MGF1", null);
        rsaSha256Mgf1 = fac.newSignatureMethod("http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1", null);
        rsaSha384Mgf1 = fac.newSignatureMethod("http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1", null);
        rsaSha512Mgf1 = fac.newSignatureMethod("http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1", null);
        rsaPss = fac.newSignatureMethod("http://www.w3.org/2007/05/xmldsig-more#rsa-pss", null);
        RSAPSSParameterSpec params = new RSAPSSParameterSpec();
        params.setTrailerField(1);
        params.setSaltLength(64);
        params.setDigestName("SHA-512");
        rsaPssSha512 = fac.newSignatureMethod("http://www.w3.org/2007/05/xmldsig-more#rsa-pss", params);

        ecdsaSha1 = fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1", null);
        ecdsaSha224 = fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224", null);
        ecdsaSha256 = fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", null);
        ecdsaSha384 = fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", null);
        ecdsaSha512 = fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512", null);
        ecdsaRipemd160 = fac.newSignatureMethod("http://www.w3.org/2007/05/xmldsig-more#ecdsa-ripemd160", null);

        kvks = new KeySelectors.KeyValueKeySelector();

        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
        rsaKpg.initialize(2048);
        rsaKeyPair = rsaKpg.genKeyPair();

        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC");
        ecKpg.initialize(256);
        ecKeyPair = ecKpg.genKeyPair();

        KeyInfoFactory kifac = fac.getKeyInfoFactory();
        rsaki = kifac.newKeyInfo(Collections.singletonList
                                 (kifac.newKeyValue(rsaKeyPair.getPublic())), "DSig.KeyInfo_1");

        boolean isIBM = "IBM Corporation".equals(System.getProperty("java.vendor"));
        if (!isIBM) {
            ecki = kifac.newKeyInfo(Collections.singletonList
                                (kifac.newKeyValue(ecKeyPair.getPublic())), "DSig.KeyInfo_1");
        }
    }

    @org.junit.jupiter.api.AfterAll
    public static void cleanup() throws Exception {
        Security.removeProvider("BC");
    }

    @org.junit.jupiter.api.Test
    public void testRSA_SHA1() throws Exception {
        test_create_signature_enveloping(rsaSha1, sha1, rsaki,
                                         rsaKeyPair.getPrivate(), kvks);
    }

    @org.junit.jupiter.api.Test
    public void testRSA_SHA_224() throws Exception {
        test_create_signature_enveloping(rsaSha224, sha1, rsaki,
                                         rsaKeyPair.getPrivate(), kvks);
    }

    @org.junit.jupiter.api.Test
    public void testRSA_SHA_256() throws Exception {
        test_create_signature_enveloping(rsaSha256, sha1, rsaki,
                                         rsaKeyPair.getPrivate(), kvks);
    }

    @org.junit.jupiter.api.Test
    public void testRSA_SHA_384() throws Exception {
        test_create_signature_enveloping(rsaSha384, sha1, rsaki,
                                         rsaKeyPair.getPrivate(), kvks);
    }

    @org.junit.jupiter.api.Test
    public void testRSA_SHA_512() throws Exception {
        test_create_signature_enveloping(rsaSha512, sha1, rsaki,
                                         rsaKeyPair.getPrivate(), kvks);
    }

    @org.junit.jupiter.api.Test
    public void testRSA_RIPEMD160() throws Exception {
        Assumptions.assumeTrue(bcInstalled);
        test_create_signature_enveloping(rsaRipemd160, sha1, rsaki,
                                         rsaKeyPair.getPrivate(), kvks);
    }

    @org.junit.jupiter.api.Test
    public void testRSA_SHA1_MGF1() throws Exception {
        Assumptions.assumeTrue(bcInstalled);
        test_create_signature_enveloping(rsaSha1Mgf1, sha1, rsaki,
                                         rsaKeyPair.getPrivate(), kvks);
    }

    @org.junit.jupiter.api.Test
    public void testRSA_SHA224_MGF1() throws Exception {
        Assumptions.assumeTrue(bcInstalled);
        test_create_signature_enveloping(rsaSha224Mgf1, sha1, rsaki,
                                         rsaKeyPair.getPrivate(), kvks);
    }

    @org.junit.jupiter.api.Test
    public void testRSA_SHA256_MGF1() throws Exception {
        Assumptions.assumeTrue(bcInstalled);
        test_create_signature_enveloping(rsaSha256Mgf1, sha1, rsaki,
                                         rsaKeyPair.getPrivate(), kvks);
    }

    @org.junit.jupiter.api.Test
    public void testRSA_SHA384_MGF1() throws Exception {
        Assumptions.assumeTrue(bcInstalled);
        test_create_signature_enveloping(rsaSha384Mgf1, sha1, rsaki,
                                         rsaKeyPair.getPrivate(), kvks);
    }

    @org.junit.jupiter.api.Test
    public void testRSA_SHA512_MGF1() throws Exception {
        Assumptions.assumeTrue(bcInstalled);
        test_create_signature_enveloping(rsaSha512Mgf1, sha1, rsaki,
                                         rsaKeyPair.getPrivate(), kvks);
    }

    @org.junit.jupiter.api.Test
    public void testRSA_PSS() throws Exception {
        Assumptions.assumeTrue(bcInstalled || org.apache.xml.security.test.dom.TestUtils.isJava11Compatible());
        test_create_signature_enveloping(rsaPss, sha1, rsaki,
                rsaKeyPair.getPrivate(), kvks);
    }

    @org.junit.jupiter.api.Test
    public void testRSA_PSS_SHA512() throws Exception {
        Assumptions.assumeTrue(bcInstalled || org.apache.xml.security.test.dom.TestUtils.isJava11Compatible());
        test_create_signature_enveloping(rsaPssSha512, sha1, rsaki,
                rsaKeyPair.getPrivate(), kvks);
    }

    @org.junit.jupiter.api.Test
    public void testECDSA_SHA1() throws Exception {
        Assumptions.assumeTrue(ecAlgParamsSupport && ecki != null);
        test_create_signature_enveloping(ecdsaSha1, sha1, ecki,
                                         ecKeyPair.getPrivate(), kvks);
    }

    @org.junit.jupiter.api.Test
    public void testECDSA_SHA224() throws Exception {
        Assumptions.assumeTrue(ecAlgParamsSupport && ecki != null);
        test_create_signature_enveloping(ecdsaSha224, sha1, ecki,
                                         ecKeyPair.getPrivate(), kvks);
    }

    @org.junit.jupiter.api.Test
    public void testECDSA_SHA256() throws Exception {
        Assumptions.assumeTrue(ecAlgParamsSupport && ecki != null);
        test_create_signature_enveloping(ecdsaSha256, sha1, ecki,
                                         ecKeyPair.getPrivate(), kvks);
    }

    @org.junit.jupiter.api.Test
    public void testECDSA_SHA384() throws Exception {
        Assumptions.assumeTrue(ecAlgParamsSupport && ecki != null);
        test_create_signature_enveloping(ecdsaSha384, sha1, ecki,
                                         ecKeyPair.getPrivate(), kvks);
    }

    @org.junit.jupiter.api.Test
    public void testECDSA_SHA512() throws Exception {
        Assumptions.assumeTrue(ecAlgParamsSupport && ecki != null);
        test_create_signature_enveloping(ecdsaSha512, sha1, ecki,
                                         ecKeyPair.getPrivate(), kvks);
    }

    @org.junit.jupiter.api.Test
    public void testECDSA_RIPEMD160() throws Exception {
        Assumptions.assumeTrue(bcInstalled);
        Assumptions.assumeTrue(ecAlgParamsSupport && ecki != null);
        test_create_signature_enveloping(ecdsaRipemd160, sha1, ecki,
                                         ecKeyPair.getPrivate(), kvks);
    }

    private void test_create_signature_enveloping(
        SignatureMethod sm, DigestMethod dm, KeyInfo ki, Key signingKey, KeySelector ks
    ) throws Exception {

        // create reference
        Reference ref = fac.newReference("#DSig.Object_1", dm, null,
                                         XMLObject.TYPE, null);

        Reference ref2 = fac.newReference("#DSig.KeyInfo_1", dm, null,
                null, null);

        // create SignedInfo
        SignedInfo si = fac.newSignedInfo(withoutComments, sm,
                Arrays.asList(ref, ref2));

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

        DOMValidateContext dvc = new DOMValidateContext(ks, doc.getDocumentElement());
        XMLSignature sig2 = fac.unmarshalXMLSignature(dvc);

        assertEquals(sig, sig2);
        assertTrue(sig2.validate(dvc));
    }

}