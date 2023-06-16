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

import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.javax.xml.crypto.KeySelectors;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * This is a testcase to validate all "merlin-xmldsig-twenty-three"
 * testcases from Baltimore
 *
 */
public class Baltimore23Test {

    private final File dir;
    private final URIDereferencer ud;

    static {
        Security.insertProviderAt
            (new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    public Baltimore23Test() {
        dir = XmlSecTestEnvironment.resolveFile("src", "test", "resources", "ie", "baltimore", "merlin-examples",
            "merlin-xmldsig-twenty-three");
        ud = new LocalHttpCacheURIDereferencer();
    }

    @Test
    public void test_signature_enveloped_dsa() throws Exception {
        String file = "signature-enveloped-dsa.xml";

        SignatureValidator validator = new SignatureValidator(dir);
        boolean coreValidity = validator.validate
            (file, new KeySelectors.KeyValueKeySelector());
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    public void test_signature_enveloping_b64_dsa() throws Exception {
        String file = "signature-enveloping-b64-dsa.xml";

        SignatureValidator validator = new SignatureValidator(dir);
        boolean coreValidity = validator.validate
            (file, new KeySelectors.KeyValueKeySelector());
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    public void test_signature_enveloping_dsa() throws Exception {
        String file = "signature-enveloping-dsa.xml";

        SignatureValidator validator = new SignatureValidator(dir);
        boolean coreValidity = validator.validate
            (file, new KeySelectors.KeyValueKeySelector());
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    public void test_signature_external_b64_dsa() throws Exception {
        String file = "signature-external-b64-dsa.xml";

        SignatureValidator validator = new SignatureValidator(dir);
        boolean coreValidity = validator.validate
            (file, new KeySelectors.KeyValueKeySelector(), ud);
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    public void test_signature_external_dsa() throws Exception {
        String file = "signature-external-dsa.xml";

        SignatureValidator validator = new SignatureValidator(dir);
        boolean coreValidity = validator.validate
            (file, new KeySelectors.KeyValueKeySelector(), ud);
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    public void test_signature_enveloping_rsa() throws Exception {
        String file = "signature-enveloping-rsa.xml";

        SignatureValidator validator = new SignatureValidator(dir);
        boolean coreValidity = validator.validate
            (file, new KeySelectors.KeyValueKeySelector());
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    public void test_signature_enveloping_hmac_sha1() throws Exception {
        String file = "signature-enveloping-hmac-sha1.xml";

        KeySelector ks = new KeySelectors.SecretKeySelector
            ("secret".getBytes(StandardCharsets.US_ASCII) );
        SignatureValidator validator = new SignatureValidator(dir);
        boolean coreValidity = validator.validate(file, ks);
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    public void test_signature_enveloping_hmac_sha1_40() throws Exception {
        String file = "signature-enveloping-hmac-sha1-40.xml";

        KeySelector ks = new KeySelectors.SecretKeySelector
            ("secret".getBytes(StandardCharsets.US_ASCII) );
        try {
            SignatureValidator validator = new SignatureValidator(dir);
            validator.validate(file, ks);
            fail("Expected HMACOutputLength exception");
        } catch (XMLSignatureException xse) {
            System.out.println(xse.getMessage());
            // pass
        }
    }

    @Test
    public void test_signature_keyname() throws Exception {
        String file = "signature-keyname.xml";

        SignatureValidator validator = new SignatureValidator(dir);
        boolean coreValidity = validator.validate
            (file, new KeySelectors.CollectionKeySelector(dir), ud);
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    public void test_signature_retrievalmethod_rawx509crt() throws Exception {
        String file = "signature-retrievalmethod-rawx509crt.xml";

        SignatureValidator validator = new SignatureValidator(dir);
        boolean coreValidity = validator.validate
            (file, new KeySelectors.CollectionKeySelector(dir), ud);
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    public void test_signature_x509_crt_crl() throws Exception {
        String file = "signature-x509-crt-crl.xml";

        SignatureValidator validator = new SignatureValidator(dir);
        boolean coreValidity = validator.validate
            (file, new KeySelectors.RawX509KeySelector(), ud);
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    public void test_signature_x509_crt() throws Exception {
        String file = "signature-x509-crt.xml";

        SignatureValidator validator = new SignatureValidator(dir);
        boolean coreValidity = validator.validate
            (file, new KeySelectors.RawX509KeySelector(), ud);
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    public void test_signature_x509_is() throws Exception {
        String file = "signature-x509-is.xml";

        SignatureValidator validator = new SignatureValidator(dir);
        boolean coreValidity = validator.validate
            (file, new KeySelectors.CollectionKeySelector(dir), ud);
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    public void test_signature_x509_ski() throws Exception {
        String file = "signature-x509-ski.xml";

        SignatureValidator validator = new SignatureValidator(dir);
        boolean coreValidity = validator.validate
            (file, new KeySelectors.CollectionKeySelector(dir), ud);
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    public void test_signature_x509_sn() throws Exception {
        String file = "signature-x509-sn.xml";

        SignatureValidator validator = new SignatureValidator(dir);
        boolean coreValidity = validator.validate
            (file, new KeySelectors.CollectionKeySelector(dir), ud);
        assertTrue(coreValidity, "Signature failed core validation");
    }

}