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
package javax.xml.crypto.test.dsig;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Collections;

import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.HMACParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.crypto.test.KeySelectors;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.xml.security.utils.XMLUtils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Test that recreates Phaos XMLDSig-3 test vectors
 * but with different keys. For now we are just focusing on
 * the exc-c14n vectors.
 *
 */
public class CreatePhaosXMLDSig3Test {

    private XMLSignatureFactory fac;

    static {
        Security.insertProviderAt
            (new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    public CreatePhaosXMLDSig3Test() throws Exception {
        fac = XMLSignatureFactory.getInstance
            ("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
    }

    @org.junit.Test
    public void test_create_hmac_sha1_exclusive_c14n_comments_detached() throws Exception {
        test_create_hmac_sha1_exclusive_c14n_comments_detached(false);
    }

    @org.junit.Test
    public void test_create_hmac_sha1_40_exclusive_c14n_comments_detached()
        throws Exception {
        try {
            test_create_hmac_sha1_exclusive_c14n_comments_detached(true);
            fail("Expected HMACOutputLength Exception");
        } catch (XMLSignatureException xse) {
            System.out.println(xse.getMessage());
            // pass
        }
    }

    private void test_create_hmac_sha1_exclusive_c14n_comments_detached(boolean fortyBit)
        throws Exception {

        // create reference
        Reference ref = fac.newReference
            ("http://www.ietf.org/rfc/rfc3161.txt",
             fac.newDigestMethod(DigestMethod.SHA1, null));

        // create SignedInfo
        HMACParameterSpec spec = null;
        if (fortyBit) {
            spec = new HMACParameterSpec(40);
        }

        SignedInfo si = fac.newSignedInfo(
            fac.newCanonicalizationMethod
                (CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS,
                 (C14NMethodParameterSpec) null),
            fac.newSignatureMethod(SignatureMethod.HMAC_SHA1, spec),
            Collections.singletonList(ref));

        // create XMLSignature
        XMLSignature sig = fac.newXMLSignature(si, null);

        Document doc = XMLUtils.newDocument();
        DOMSignContext dsc = new DOMSignContext
            (new KeySelectors.SecretKeySelector
             ("test".getBytes(StandardCharsets.US_ASCII)), doc);
        dsc.putNamespacePrefix(XMLSignature.XMLNS, "dsig");
        URIDereferencer ud = new LocalHttpCacheURIDereferencer();
        dsc.setURIDereferencer(ud);

        sig.sign(dsc);
        TestUtils.validateSecurityOrEncryptionElement(doc.getDocumentElement());

        DOMValidateContext dvc = new DOMValidateContext
            (new KeySelectors.SecretKeySelector
             ("test".getBytes(StandardCharsets.US_ASCII)), doc);
        dvc.setURIDereferencer(ud);

        XMLSignature sig2 = fac.unmarshalXMLSignature(dvc);

        assertEquals(sig, sig2);

        assertTrue(sig2.validate(dvc));
    }

    @org.junit.Test
    public void test_create_hmac_sha1_exclusive_c14n_enveloped() throws Exception {

        // create reference
        Reference ref = fac.newReference("",
            fac.newDigestMethod(DigestMethod.SHA1, null),
            Collections.singletonList(fac.newTransform(Transform.ENVELOPED,
            (TransformParameterSpec) null)),
            null, null);

        // create SignedInfo
        SignedInfo si = fac.newSignedInfo(
            fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                (C14NMethodParameterSpec) null),
            fac.newSignatureMethod(SignatureMethod.HMAC_SHA1, null),
            Collections.singletonList(ref));

        // create XMLSignature
        XMLSignature sig = fac.newXMLSignature(si, null);

        Document doc = XMLUtils.newDocument();
        Element player = doc.createElementNS(null, "player");
        player.setAttributeNS(null, "bats", "left");
        player.setAttributeNS(null, "id", "10012");
        player.setAttributeNS(null, "throws", "right");
        Element name = doc.createElementNS(null, "name");
        name.appendChild(doc.createTextNode("Alfonso Soriano"));
        Element position = doc.createElementNS(null, "position");
        position.appendChild(doc.createTextNode("2B"));
        Element team = doc.createElementNS(null, "team");
        team.appendChild(doc.createTextNode("New York Yankees"));
        player.appendChild(doc.createComment(" Here's a comment "));
        player.appendChild(name);
        player.appendChild(position);
        player.appendChild(team);
        doc.appendChild(player);

        DOMSignContext dsc = new DOMSignContext
            (new KeySelectors.SecretKeySelector
             ("test".getBytes(StandardCharsets.US_ASCII)), player);
        dsc.putNamespacePrefix(XMLSignature.XMLNS, "dsig");

        sig.sign(dsc);
        TestUtils.validateSecurityOrEncryptionElement(player.getLastChild());

        DOMValidateContext dvc = new DOMValidateContext
            (new KeySelectors.SecretKeySelector
             ("test".getBytes(StandardCharsets.US_ASCII)), player.getLastChild());

        XMLSignature sig2 = fac.unmarshalXMLSignature(dvc);

        assertEquals(sig, sig2);

        assertTrue(sig2.validate(dvc));
    }

}