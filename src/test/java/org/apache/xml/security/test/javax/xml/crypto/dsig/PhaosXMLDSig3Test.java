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
import java.nio.charset.StandardCharsets;
import java.security.Security;

import javax.xml.crypto.KeySelector;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.dom.DOMValidateContext;

import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.javax.xml.crypto.KeySelectors;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * This is a testcase to validate all "phaos-xmldsig-three"
 * testcases from Phaos
 *
 */
class PhaosXMLDSig3Test {

    private final SignatureValidator validator;
    private final File base;
    private final URIDereferencer ud;

    static {
        Security.insertProviderAt
        (new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    public PhaosXMLDSig3Test() {
        base = XmlSecTestEnvironment.resolveFile("src", "test", "resources", "com", "phaos", "phaos-xmldsig-three");
        validator = new SignatureValidator(base);
        ud = new LocalHttpCacheURIDereferencer();
    }

    @Test
    void test_signature_dsa_detached() throws Exception {
        String file = "signature-dsa-detached.xml";

        DOMValidateContext vc = validator.getValidateContext
        (file, new KeySelectors.RawX509KeySelector());
        vc.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);
        vc.setURIDereferencer(ud);

        boolean coreValidity = validator.validate(vc);
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void test_signature_dsa_enveloped() throws Exception {
        String file = "signature-dsa-enveloped.xml";

        boolean coreValidity =
            validator.validate(file, new KeySelectors.RawX509KeySelector());
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void test_signature_dsa_enveloping() throws Exception {
        String file = "signature-dsa-enveloping.xml";

        boolean coreValidity =
            validator.validate(file, new KeySelectors.RawX509KeySelector());
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void test_signature_dsa_manifest() throws Exception {
        String file = "signature-dsa-manifest.xml";

        boolean coreValidity =
            validator.validate(file, new KeySelectors.KeyValueKeySelector());
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void test_signature_hmac_sha1_40_c14n_comments_detached()
    throws Exception {
        String file = "signature-hmac-sha1-40-c14n-comments-detached.xml";

        KeySelector ks = new KeySelectors.SecretKeySelector
            ("test".getBytes(StandardCharsets.US_ASCII) );
        try {
            validator.validate(file, ks);
            fail("Expected HMACOutputLength Exception");
        } catch (XMLSignatureException xse) {
            //System.out.println(xse.getMessage());
            // pass
        }
    }

    @Test
    void test_signature_hmac_sha1_40_exclusive_c14n_comments_detached()
    throws Exception {
        String file = "signature-hmac-sha1-40-exclusive-c14n-comments-detached.xml";

        KeySelector ks = new KeySelectors.SecretKeySelector
            ("test".getBytes(StandardCharsets.US_ASCII) );
        try {
            validator.validate(file, ks);
            fail("Expected HMACOutputLength Exception");
        } catch (XMLSignatureException xse) {
            //System.out.println(xse.getMessage());
            // pass
        }
    }

    @Test
    void test_signature_hmac_sha1_exclusive_c14n_comments_detached()
    throws Exception {
        String file = "signature-hmac-sha1-exclusive-c14n-comments-detached.xml";

        KeySelector ks = new KeySelectors.SecretKeySelector
            ("test".getBytes(StandardCharsets.US_ASCII) );
        boolean coreValidity = validator.validate(file, ks, ud);
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void test_signature_hmac_sha1_exclusive_c14n_enveloped()
    throws Exception {
        String file = "signature-hmac-sha1-exclusive-c14n-enveloped.xml";

        KeySelector ks = new KeySelectors.SecretKeySelector
            ("test".getBytes(StandardCharsets.US_ASCII) );
        boolean coreValidity = validator.validate(file, ks);
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void test_signature_rsa_detached_b64_transform() throws Exception {
        String file = "signature-rsa-detached-b64-transform.xml";

        boolean coreValidity =
            validator.validate(file, new KeySelectors.KeyValueKeySelector());
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void test_signature_rsa_detached_xpath_transform() throws Exception {
        String file = "signature-rsa-detached-xpath-transform.xml";

        boolean coreValidity =
            validator.validate(file, new KeySelectors.KeyValueKeySelector());
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void test_signature_rsa_detached_xslt_transform_bad_rm() throws Exception {
        String file = "signature-rsa-detached-xslt-transform-bad-retrieval-method.xml";

        try {
            validator.validate(file,
                               new KeySelectors.CollectionKeySelector(base));
            fail("Should throw XMLSignatureException for using DSA key with " +
            "RSA algorithm");
        } catch (XMLSignatureException xse) {}
    }

    @Test
    void test_signature_rsa_detached_xslt_transform_rm() throws Exception {
        String file = "signature-rsa-detached-xslt-transform-retrieval-method.xml";

        boolean coreValidity =
            validator.validate(file,
                               new KeySelectors.CollectionKeySelector(base));
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void test_signature_rsa_detached_xslt_transform() throws Exception {
        String file = "signature-rsa-detached-xslt-transform.xml";

        boolean coreValidity =
            validator.validate(file, new KeySelectors.KeyValueKeySelector());
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void test_signature_rsa_detached() throws Exception {
        String file = "signature-rsa-detached.xml";

        DOMValidateContext vc = validator.getValidateContext
            (file, new KeySelectors.RawX509KeySelector());
        vc.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);
        vc.setURIDereferencer(ud);
        boolean coreValidity = validator.validate(vc);
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void test_signature_rsa_enveloped_bad_digest_val() throws Exception {
        String file = "signature-rsa-enveloped-bad-digest-val.xml";

        boolean coreValidity =
            validator.validate(file, new KeySelectors.RawX509KeySelector());
        assertFalse(coreValidity, "Signature should fail core validation");
    }

    @Test
    void test_signature_rsa_enveloped() throws Exception {
        String file = "signature-rsa-enveloped.xml";

        boolean coreValidity =
            validator.validate(file, new KeySelectors.RawX509KeySelector());
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void test_signature_rsa_enveloping() throws Exception {
        String file = "signature-rsa-enveloping.xml";

        boolean coreValidity =
            validator.validate(file, new KeySelectors.RawX509KeySelector());
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void test_signature_rsa_manifest_x509_data_cert_chain() throws Exception {
        String file = "signature-rsa-manifest-x509-data-cert-chain.xml";

        boolean coreValidity =
            validator.validate(file, new KeySelectors.RawX509KeySelector());
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void test_signature_rsa_manifest_x509_data_cert() throws Exception {
        String file = "signature-rsa-manifest-x509-data-cert.xml";

        boolean coreValidity =
            validator.validate(file, new KeySelectors.RawX509KeySelector());
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void test_signature_rsa_manifest_x509_data_issuer_serial() throws Exception {
        String file = "signature-rsa-manifest-x509-data-issuer-serial.xml";

        boolean coreValidity = validator.validate(file,
                                                  new KeySelectors.CollectionKeySelector(base));
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void test_signature_rsa_manifest_x509_data_ski() throws Exception {
        String file = "signature-rsa-manifest-x509-data-ski.xml";

        boolean coreValidity = validator.validate(file,
                                                  new KeySelectors.CollectionKeySelector(base));
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void test_signature_rsa_manifest_x509_data_subject_name() throws Exception {
        String file = "signature-rsa-manifest-x509-data-subject-name.xml";

        boolean coreValidity = validator.validate(file,
                                                  new KeySelectors.CollectionKeySelector(base));
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void test_signature_rsa_manifest_x509_data() throws Exception {
        String file = "signature-rsa-manifest-x509-data.xml";

        boolean coreValidity =
            validator.validate(file, new KeySelectors.RawX509KeySelector());
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void test_signature_rsa_manifest() throws Exception {
        String file = "signature-rsa-manifest.xml";

        boolean coreValidity =
            validator.validate(file, new KeySelectors.KeyValueKeySelector());
        assertTrue(coreValidity, "Signature failed core validation");
    }

}