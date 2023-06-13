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
/*
 * Copyright 2005 Sun Microsystems, Inc. All rights reserved.
 */
package org.apache.xml.security.test.javax.xml.crypto.dsig;

import java.io.File;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignContext;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.XMLValidateContext;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * Unit test for javax.xml.crypto.dsig.XMLSignature
 *
 */
class XMLSignatureTest {
    private static final String id = "id";
    private static final String sigValueId = "signatureValueId";
    private static final String DSA_SHA256 = "http://www.w3.org/2009/xmldsig11#dsa-sha256";

    private final XMLSignatureFactory fac;
    private final KeyInfoFactory kifac;
    private final SignedInfo defSi;
    private final KeyInfo defKi;
    private final List<XMLObject> objs;
    private final Key[] SIGN_KEYS;
    private final Key[] VALIDATE_KEYS;
    private final SignatureMethod[] SIG_METHODS;
    private final URIDereferencer ud;

    static {
        Security.insertProviderAt
            (new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    public XMLSignatureTest() throws Exception {
        fac = XMLSignatureFactory.getInstance
            ("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
        kifac = KeyInfoFactory.getInstance
            ("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());

        // set up the corresponding SignatureMethod
        SIG_METHODS = new SignatureMethod[3];
        SIG_METHODS[0] = fac.newSignatureMethod(SignatureMethod.DSA_SHA1, null);
        SIG_METHODS[1] = fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null);
        SIG_METHODS[2] = fac.newSignatureMethod(SignatureMethod.HMAC_SHA1, null);
        // set up the signingKeys
        SIGN_KEYS = new Key[3];
        SIGN_KEYS[0] = TestUtils.getPrivateKey("DSA", 1024);
        SIGN_KEYS[1] = TestUtils.getPrivateKey("RSA", 2048);
        SIGN_KEYS[2] = new SecretKeySpec(new byte[16], "HmacSHA1");
        // set up the validatingKeys
        VALIDATE_KEYS = new Key[3];
        VALIDATE_KEYS[0] = TestUtils.getPublicKey("DSA", 1024);
        VALIDATE_KEYS[1] = TestUtils.getPublicKey("RSA", 2048);
        VALIDATE_KEYS[2] = new SecretKeySpec(new byte[16], "HmacSHA1");
        defSi = createSignedInfo(SIG_METHODS[0]);
        defKi = kifac.newKeyInfo
            (Collections.singletonList(kifac.newKeyName("Alice")));
        objs = Collections.singletonList
            (fac.newXMLObject(null, null, null, null));
        ud = new LocalHttpCacheURIDereferencer();
    }

    @SuppressWarnings("rawtypes")
    @Test
    void testConstructor() throws Exception {
        XMLSignature sig = null;
        // test XMLSignatureFactory.newXMLSignature(SignedInfo, KeyInfo)
        // and XMLSignatureFactory.newXMLSignature(SignedInfo,
        //          KeyInfo, List, String, String)
        // for generating XMLSignature objects
        for (int i = 0; i < 2; i++) {
            try {
                if (i == 0) {
                    sig = fac.newXMLSignature(null, defKi);
                } else if (i == 1) {
                    sig = fac.newXMLSignature(null, defKi, objs, id, sigValueId);
                }
                fail("Should throw a NPE for null references");
            } catch (NullPointerException npe) {
            } catch (Exception ex) {
                fail("Should throw a NPE instead of " + ex +
                     " for null references");
            }
        }
        try {
            // use raw List type to test for invalid entries
            List invalidObjects = new ArrayList();
            addEntryToRawList(invalidObjects, "wrongType");
            fac.newXMLSignature(defSi, defKi, invalidObjects, id, sigValueId);
            fail("Should throw a CCE for invalid objects");
        } catch (ClassCastException cce) {
        } catch (Exception ex) {
            fail("Should throw a CCE instead of " + ex +
                 " for invalid objects");
        }
        sig = fac.newXMLSignature(defSi, defKi, objs, id, sigValueId);
        assertEquals(sig.getId(), id);
        assertEquals(sig.getKeyInfo(), defKi);
        assertArrayEquals(sig.getObjects().toArray(), objs.toArray());
        assertNull(sig.getSignatureValue().getValue());
        assertEquals(sig.getSignatureValue().getId(), sigValueId);
        assertEquals(sig.getSignedInfo(), defSi);

        sig = fac.newXMLSignature(defSi, defKi);
        assertNull(sig.getId());
        assertEquals(sig.getKeyInfo(), defKi);
        assertThat(sig.getObjects(), hasSize(0));
        assertNull(sig.getSignatureValue().getValue());
        assertNull(sig.getSignatureValue().getId());
        assertEquals(sig.getSignedInfo(), defSi);
    }

    @Test
    void testisFeatureSupported() throws Exception {

        XMLSignature sig = fac.newXMLSignature(defSi, null);

        try {
            sig.isFeatureSupported(null);
            fail("Should raise a NPE for null feature");
        } catch (NullPointerException npe) {}

        assertFalse(sig.isFeatureSupported("not supported"));
    }

    @Test
    void testsignANDvalidate() throws Exception {
        XMLSignature sig;
        SignedInfo si;
        KeyInfo ki = null;
        XMLSignContext signContext;
        XMLValidateContext validateContext;
        boolean status = true;
        for (int i = SIGN_KEYS.length-1; i>=0 ; i--) {
            si = createSignedInfo(SIG_METHODS[i]);
            if (VALIDATE_KEYS[i] instanceof PublicKey) {
                ki = kifac.newKeyInfo(Collections.singletonList
                    (kifac.newKeyValue((PublicKey) VALIDATE_KEYS[i])));
            } else {
                ki = kifac.newKeyInfo(Collections.singletonList
                    (kifac.newKeyName("testuser")));
            }
            sig = fac.newXMLSignature(si, ki, objs, id, sigValueId);
            Document doc = TestUtils.newDocument();
            signContext = new DOMSignContext(SIGN_KEYS[i], doc);
            signContext.setURIDereferencer(ud);
            sig.sign(signContext);
            validateContext = new DOMValidateContext
                (VALIDATE_KEYS[i], doc.getDocumentElement());
            validateContext.setURIDereferencer(ud);
            if (!sig.validate(validateContext)) {
                status = false;
                TestUtils.dumpDocument(doc, "signatureTest_out"+i+".xml");
            }
        }
        assertTrue(status);
    }

    @Test
    void testSignWithProvider() throws Exception {
        XMLSignature sig;
        SignedInfo si;
        KeyInfo ki = null;
        XMLSignContext signContext;
        Provider p = new TestProvider();
        for (int i = SIGN_KEYS.length-1; i>=0 ; i--) {
            si = createSignedInfo(SIG_METHODS[i]);
            if (VALIDATE_KEYS[i] instanceof PublicKey) {
                ki = kifac.newKeyInfo(Collections.singletonList
                    (kifac.newKeyValue((PublicKey) VALIDATE_KEYS[i])));
            } else {
                ki = kifac.newKeyInfo(Collections.singletonList
                    (kifac.newKeyName("testuser")));
            }
            sig = fac.newXMLSignature(si, ki, objs, id, sigValueId);
            Document doc = TestUtils.newDocument();
            signContext = new DOMSignContext(SIGN_KEYS[i], doc);
            if (SIGN_KEYS[i] instanceof PrivateKey) {
                signContext.setProperty("org.jcp.xml.dsig.internal.dom.SignatureProvider", p);
            } else {
                signContext.setProperty("org.jcp.xml.dsig.internal.dom.MacProvider", p);
            }

            signContext.setURIDereferencer(ud);
            try {
                sig.sign(signContext);
                fail("Should have failed because TestProvider does not " +
                     "support " + SIGN_KEYS[i].getAlgorithm());
            } catch (Exception e) {
                assertTrue(e.getCause() instanceof NoSuchAlgorithmException, e.getMessage());
            }
        }
    }

    @Test
    void testSignWithEmptyNSPrefix() throws Exception {
        SignedInfo si = createSignedInfo(SIG_METHODS[1]);
        KeyInfo ki = kifac.newKeyInfo(Collections.singletonList
                    (kifac.newKeyValue((PublicKey) VALIDATE_KEYS[1])));
        XMLSignature sig = fac.newXMLSignature(si, ki, objs, id, sigValueId);
        Document doc = TestUtils.newDocument();
        XMLSignContext signContext = new DOMSignContext(SIGN_KEYS[1], doc);
        signContext.putNamespacePrefix(XMLSignature.XMLNS, "");
        signContext.setURIDereferencer(ud);
        sig.sign(signContext);
/*
        StringWriter sw = new StringWriter();
        dumpDocument(doc, sw);
        System.out.println(sw);
*/
    }

    @Test
    void testSignWithReferenceManifestDependencies() throws Exception {
        // create references
        DigestMethod dm = fac.newDigestMethod(DigestMethod.SHA1, null);
        List<Reference> refs = Collections.singletonList(fac.newReference("#object-1", dm));

        // create SignedInfo
        CanonicalizationMethod cm = fac.newCanonicalizationMethod
            (CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null);
        SignedInfo si = fac.newSignedInfo(cm, SIG_METHODS[1], refs);

        // create objects
        List<XMLObject> objs = new ArrayList<>();

        // Object 1
        List<Reference> manRefs = Collections.singletonList
            (fac.newReference("#object-2", dm));
        objs.add(fac.newXMLObject(Collections.singletonList
            (fac.newManifest(manRefs, "manifest-1")), "object-1", null, null));

        // Object 2
        Document doc = TestUtils.newDocument();
        Element nc = doc.createElementNS(null, "NonCommentandus");
        nc.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns", "");
        nc.appendChild(doc.createComment(" Commentandum "));
        objs.add(fac.newXMLObject(Collections.singletonList
            (new DOMStructure(nc)), "object-2", null, null));

        KeyInfo ki = kifac.newKeyInfo(Collections.singletonList
                    (kifac.newKeyValue((PublicKey) VALIDATE_KEYS[1])));

        // create XMLSignature
        XMLSignature sig = fac.newXMLSignature(si, ki, objs, "signature", null);
        DOMSignContext dsc = new DOMSignContext(SIGN_KEYS[1], doc);

        sig.sign(dsc);

/*
        StringWriter sw = new StringWriter();
        dumpDocument(doc, sw);
        System.out.println(sw);
*/

        DOMValidateContext dvc = new DOMValidateContext
            (VALIDATE_KEYS[1], doc.getDocumentElement());
        dvc.setProperty("org.jcp.xml.dsig.validateManifests", Boolean.TRUE);
        XMLSignature sig2 = fac.unmarshalXMLSignature(dvc);

        if (!sig.equals(sig2)) {
            throw new Exception
                ("Unmarshalled signature is not equal to generated signature");
        }
        if (!sig2.validate(dvc)) {
            throw new Exception("Validation of generated signature failed");
        }
    }

    @Test
    void testSignTemplateWithObjectNSDefs() throws Exception {
        File f = resolveFile(
            "src/test/resources/org/apache/xml/security/test/javax/xml/crypto/dsig/signature-enveloping-rsa-template.xml");
        Document doc = XMLUtils.read(f, false);

        // Find Signature element
        NodeList nl =
            doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nl.getLength() == 0) {
            throw new Exception("Cannot find Signature element");
        }
        DOMStructure domSignature = new DOMStructure(nl.item(0));
        // unmarshal the XMLSignature
        XMLSignature signature = fac.unmarshalXMLSignature(domSignature);

        // create copy of Signature
        XMLSignature newSignature = fac.newXMLSignature
            (signature.getSignedInfo(), null, signature.getObjects(),
             signature.getId(), signature.getSignatureValue().getId());

        // Sign the template
        Node parent = domSignature.getNode().getParentNode();
        DOMSignContext signContext = new DOMSignContext(SIGN_KEYS[0], parent);
        // remove the signature node (since it will get recreated)
        parent.removeChild(domSignature.getNode());
        newSignature.sign(signContext);

        // check that Object element retained namespace definitions
        Element objElem = (Element)parent.getFirstChild().getLastChild();
        Attr a = objElem.getAttributeNode("xmlns:test");
        if (!"http://www.example.org/ns".equals(a.getValue())) {
            throw new Exception("Object namespace definition not retained");
        }
    }

    @Test
    void testCreateSignatureWithEmptyId() throws Exception {
        // create references
        DigestMethod dm = fac.newDigestMethod(DigestMethod.SHA1, null);
        List<Reference> refs = Collections.singletonList
            (fac.newReference("#", dm));

        // create SignedInfo
        CanonicalizationMethod cm = fac.newCanonicalizationMethod
            (CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null);
        SignedInfo si = fac.newSignedInfo(cm, SIG_METHODS[1], refs);

        // create object with empty id
        Document doc = TestUtils.newDocument();
        XMLObject obj = fac.newXMLObject(Collections.singletonList
            (new DOMStructure(doc.createTextNode("I am the text."))),
            "", "text/plain", null);

        KeyInfo ki = kifac.newKeyInfo(Collections.singletonList
                    (kifac.newKeyValue((PublicKey) VALIDATE_KEYS[1])));

        // create XMLSignature
        XMLSignature sig = fac.newXMLSignature(si, ki,
                                               Collections.singletonList(obj),
                                               "signature", null);
        DOMSignContext dsc = new DOMSignContext(SIGN_KEYS[1], doc);
        sig.sign(dsc);
    }

    @Test
    void testCreateDSA2048Signature() throws Exception {

        // check if SHA256withDSA is supported
        boolean gotSHA256withDSA = false;
        try {
            Signature.getInstance("SHA256withDSA");
            gotSHA256withDSA = true;
        } catch (NoSuchAlgorithmException e) {}
        Assumptions.assumeTrue(gotSHA256withDSA);

        SignatureMethod sm = fac.newSignatureMethod(DSA_SHA256, null);
        SignedInfo si = createSignedInfo(sm);
        KeyInfo ki = kifac.newKeyInfo(Collections.singletonList
            (kifac.newKeyValue(TestUtils.getPublicKey("DSA", 2048))));
        XMLSignature sig = fac.newXMLSignature(si, ki, objs, id, sigValueId);
        Document doc = TestUtils.newDocument();
        XMLSignContext signContext =
            new DOMSignContext(TestUtils.getPrivateKey("DSA", 2048), doc);
        signContext.setURIDereferencer(ud);
        sig.sign(signContext);
        XMLValidateContext validateContext = new DOMValidateContext
            (TestUtils.getPublicKey("DSA", 2048), doc.getDocumentElement());
        validateContext.setURIDereferencer(ud);
        assertTrue(sig.validate(validateContext));
    }

    @Test
    void testBadXPointer() throws Exception {
        Document doc = TestUtils.newDocument();
        Element root = doc.createElementNS(null, "Root");
        SignatureMethod sm = SIG_METHODS[1];
        CanonicalizationMethod cm = fac.newCanonicalizationMethod(
            CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec)null);
        DigestMethod dm = fac.newDigestMethod(DigestMethod.SHA256, null);
        Transform tr = fac.newTransform(
            Transform.ENVELOPED, (TransformParameterSpec)null);
        KeyInfo ki = kifac.newKeyInfo(Collections.singletonList
            (kifac.newKeyValue((PublicKey)VALIDATE_KEYS[1])));
        XMLObject xo = fac.newXMLObject(
            Collections.singletonList(new DOMStructure(root)), "a", null, null);
        SignedInfo si = fac.newSignedInfo(cm, sm,
            Collections.singletonList(fac.newReference("#xpointer(id('a))",
                dm, Collections.singletonList(tr), null, null)));
        XMLSignature sig = fac.newXMLSignature(si, ki,
            Collections.singletonList(xo), id, sigValueId);
        XMLSignContext signContext = new DOMSignContext(SIGN_KEYS[1], doc);
        try {
            sig.sign(signContext);
            throw new Exception("Failed: expected XMLSignatureException");
        } catch (XMLSignatureException xse) {
            if (!(xse.getCause() instanceof URIReferenceException) &&
                !(xse.getMessage().contains("Could not find a resolver"))) {
                throw new Exception("Failed: wrong cause or reason", xse);
            }
        }
    }

    private SignedInfo createSignedInfo(SignatureMethod sm) throws Exception {
        // set up the building blocks
        CanonicalizationMethod cm = fac.newCanonicalizationMethod
            (CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
             (C14NMethodParameterSpec) null);
        DigestMethod dm = fac.newDigestMethod(DigestMethod.SHA1, null);
        List<Reference> refs = Collections.singletonList(fac.newReference
            ("http://www.w3.org/Signature/2002/04/xml-stylesheet.b64", dm));
        return fac.newSignedInfo(cm, sm, refs);
    }

    @SuppressWarnings({
     "unchecked", "rawtypes"
    })
    private static void addEntryToRawList(List list, Object entry) {
        list.add(entry);
    }

    static class TestProvider extends Provider {
        private static final long serialVersionUID = 1L;

        TestProvider() {
            super("TestProvider", "0", "TestProvider");
        }
    }
}
