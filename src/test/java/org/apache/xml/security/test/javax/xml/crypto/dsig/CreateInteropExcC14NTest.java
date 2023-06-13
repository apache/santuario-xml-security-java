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
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.javax.xml.crypto.KeySelectors;
import org.w3c.dom.Comment;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test that recreates interop exc C14N test vectors
 * but with different keys.
 *
 */
public class CreateInteropExcC14NTest {

    private final XMLSignatureFactory fac;
    private final KeyInfoFactory kifac;
    private final KeyStore ks;
    private final Key signingKey;
    private final PublicKey validatingKey;

    static {
        Security.insertProviderAt
            (new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    public CreateInteropExcC14NTest() throws Exception {
        fac = XMLSignatureFactory.getInstance
            ("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
        kifac = fac.getKeyInfoFactory();

        ks = XmlSecTestEnvironment.getTestKeyStore();
        Certificate signingCert = ks.getCertificate("mullan");
        signingKey = ks.getKey("mullan", "changeit".toCharArray());
        validatingKey = signingCert.getPublicKey();
    }

    @org.junit.jupiter.api.Test
    public void test_create_Y1() throws Exception {
        List<Reference> refs = new ArrayList<>(4);

        // create reference 1
        refs.add(fac.newReference
            ("#xpointer(id('to-be-signed'))",
             fac.newDigestMethod(DigestMethod.SHA1, null),
             Collections.singletonList
                (fac.newTransform(CanonicalizationMethod.EXCLUSIVE,
                 (TransformParameterSpec) null)),
             null, null));

        // create reference 2
        List<String> prefixList = new ArrayList<>(2);
        prefixList.add("bar");
        prefixList.add("#default");
        ExcC14NParameterSpec params = new ExcC14NParameterSpec(prefixList);
        refs.add(fac.newReference
            ("#xpointer(id('to-be-signed'))",
             fac.newDigestMethod(DigestMethod.SHA1, null),
             Collections.singletonList
                (fac.newTransform(CanonicalizationMethod.EXCLUSIVE, params)),
             null, null));

        // create reference 3
        refs.add(fac.newReference
            ("#xpointer(id('to-be-signed'))",
             fac.newDigestMethod(DigestMethod.SHA1, null),
             Collections.singletonList(fac.newTransform
                (CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS,
                 (TransformParameterSpec) null)),
             null, null));

        // create reference 4
        prefixList = new ArrayList<>(2);
        prefixList.add("bar");
        prefixList.add("#default");
        params = new ExcC14NParameterSpec(prefixList);
        refs.add(fac.newReference
            ("#xpointer(id('to-be-signed'))",
             fac.newDigestMethod(DigestMethod.SHA1, null),
             Collections.singletonList(fac.newTransform
                (CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS,
                 params)),
             null, null));

        // create SignedInfo
        SignedInfo si = fac.newSignedInfo(
            fac.newCanonicalizationMethod
                (CanonicalizationMethod.EXCLUSIVE,
                 (C14NMethodParameterSpec) null),
            fac.newSignatureMethod(SignatureMethod.DSA_SHA1, null), refs);

        // create KeyInfo
        List<KeyValue> kits = new ArrayList<>(2);
        kits.add(kifac.newKeyValue(validatingKey));
        KeyInfo ki = kifac.newKeyInfo(kits);

        // create Objects
        Document doc = TestUtils.newDocument();
        Element baz = doc.createElementNS("urn:bar", "bar:Baz");
        Comment com = doc.createComment(" comment ");
        baz.appendChild(com);
        XMLObject obj = fac.newXMLObject(Collections.singletonList
            (new DOMStructure(baz)), "to-be-signed", null, null);

        // create XMLSignature
        XMLSignature sig = fac.newXMLSignature
            (si, ki, Collections.singletonList(obj), null, null);

        Element foo = doc.createElementNS("urn:foo", "Foo");
        foo.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns", "urn:foo");
        foo.setAttributeNS
            ("http://www.w3.org/2000/xmlns/", "xmlns:bar", "urn:bar");
        doc.appendChild(foo);

        DOMSignContext dsc = new DOMSignContext(signingKey, foo);
        dsc.putNamespacePrefix(XMLSignature.XMLNS, "dsig");

        sig.sign(dsc);
        TestUtils.validateSecurityOrEncryptionElement(foo.getLastChild());

        DOMValidateContext dvc = new DOMValidateContext
            (new KeySelectors.KeyValueKeySelector(), foo.getLastChild());
        XMLSignature sig2 = fac.unmarshalXMLSignature(dvc);

        assertEquals(sig, sig2);

        assertTrue(sig2.validate(dvc));
    }

}
