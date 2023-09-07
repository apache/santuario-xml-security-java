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


import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.Security;

import javax.xml.crypto.Data;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;

import org.apache.xml.security.test.javax.xml.crypto.KeySelectors;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xml.security.utils.resolver.implementations.ResolverLocalFilesystem;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * This is a testcase that validates various signatures
 *
 */
class ValidateSignatureTest {

    private final SignatureValidator validator;
    private final File dir;

    static {
        Security.insertProviderAt(new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
        ResourceResolver.register(new ResolverLocalFilesystem(), false);
    }

    public ValidateSignatureTest() {
        dir = resolveFile("src", "test", "resources", "org", "apache", "xml", "security", "test", "javax", "xml", "crypto", "dsig");
        validator = new SignatureValidator(dir);
    }

    /**
     * Validates a signature that references an element with an ID attribute.
     * The element's ID needs to be registered so that it can be found.
     */
    @Test
    void test_signature_with_ID() throws Exception {
        String file = "envelopingSignature.xml";

        DOMValidateContext vc = validator.getValidateContext
            (file, new KeySelectors.KeyValueKeySelector());
        Document doc = vc.getNode().getOwnerDocument();
        NodeList nl = doc.getElementsByTagName("Assertion");
        vc.setIdAttributeNS((Element) nl.item(0), null, "AssertionID");
        boolean coreValidity = validator.validate(vc);
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void test_signature_external_c14n_xmlattrs() throws Exception {
        String file = "signature-external-c14n-xmlatrs.xml";

        boolean coreValidity = validator.validate(file,
            new KeySelectors.SecretKeySelector("secret".getBytes(StandardCharsets.US_ASCII)));
        assertTrue(coreValidity, "Signature failed core validation");
    }

    /**
     * This test checks that the signature is verified before the references.
     */
    @Test
    void test_invalid_signature() throws Exception {
        InvalidURIDereferencer ud = new InvalidURIDereferencer();

        boolean coreValidity = validator.validate("invalid-signature.xml",
            new KeySelectors.KeyValueKeySelector(), ud);
        assertFalse(coreValidity, "Invalid signature should fail!");
        assertTrue(ud.dereferenced, "References validated before signature");
    }

    @Test
    void test_signature_enveloping_hmac_sha1_trunclen_0() throws Exception {
        try {
            validator.validate
                ("signature-enveloping-hmac-sha1-trunclen-0-attack.xml",
                new KeySelectors.SecretKeySelector("secret".getBytes(StandardCharsets.US_ASCII)));
            fail("Expected HMACOutputLength exception");
        } catch (XMLSignatureException xse) {
            // System.out.println(xse.getMessage());
            // pass
        }
    }

    @Test
    void test_signature_enveloping_hmac_sha1_trunclen_8() throws Exception {

        try {
            validator.validate
                ("signature-enveloping-hmac-sha1-trunclen-8-attack.xml",
                new KeySelectors.SecretKeySelector("secret".getBytes(StandardCharsets.US_ASCII)));
            fail("Expected HMACOutputLength exception");
        } catch (XMLSignatureException xse) {
            // System.out.println(xse.getMessage());
            // pass
        }
    }

    // Bug 47761: validates an xml signature containing a reference with
    // xmlns:xml attributes. C14n should not emit these attributes.
    @Test
    void test_signature_exclc14n_xmlnamespace() throws Exception {
        String file = "demo.signed.xml";
        boolean coreValidity = validator.validate(file,
            new KeySelectors.RawX509KeySelector());
        assertTrue(coreValidity, "Signature failed core validation");
    }

    // Bug https://issues.apache.org/jira/browse/SANTUARIO-295
    // Validates a signature with an XPathFilter2 Transform with an intersect
    // filter that produces an empty node-set.
    @Test
    void test_signature_xpathfilter2() throws Exception {
        String file = "xmldsig-xfilter2.xml";
        boolean coreValidity = validator.validate
            (file, new KeySelectors.KeyValueKeySelector());
        assertTrue(coreValidity, "Signature failed core validation");
    }

    /**
     * Set flag if called.
     */
    static class InvalidURIDereferencer implements URIDereferencer {
        boolean dereferenced = false;
        private final URIDereferencer ud =
            XMLSignatureFactory.getInstance().getURIDereferencer();

        @Override
        public Data dereference(final URIReference ref, XMLCryptoContext ctx)
        throws URIReferenceException {
            dereferenced = true;

            // fallback
            return ud.dereference(ref, ctx);
        }
    }

}