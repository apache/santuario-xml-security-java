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
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.xml.crypto.KeySelector;

import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.javax.xml.crypto.KeySelectors;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * This is a testcase to validate all the W3C xmldsig XMLDSig11 testcases.
 *
 */
class InteropXMLDSig11Test {

    private final SignatureValidator validator;
    private final File dir;
    private final KeySelector kvks, sks;
    private boolean ecSupport = true;

    static {
        Security.insertProviderAt
            (new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    public InteropXMLDSig11Test() throws Exception {
        // check if EC is supported
        try {
            KeyFactory.getInstance("EC");
        } catch (NoSuchAlgorithmException nsae) {
            ecSupport = false;
        }
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))) {
            ecSupport = false;
        }
        dir = XmlSecTestEnvironment.resolveFile("src", "test", "resources", "org", "w3c", "www", "interop", "xmldsig11");
        validator = new SignatureValidator(dir);
        kvks = new KeySelectors.KeyValueKeySelector();
        sks = new KeySelectors.SecretKeySelector("testkey".getBytes(StandardCharsets.US_ASCII));
    }

    @Test
    void test_enveloping_p256_sha1() throws Exception {
        if (ecSupport) {
            test_xmldsig11("signature-enveloping-p256_sha1", "oracle");
        }
    }

    @Test
    void test_enveloping_p256_sha256() throws Exception {
        if (ecSupport) {
            test_xmldsig11("signature-enveloping-p256_sha256", "oracle");
        }
    }

    @Test
    void test_enveloping_p256_sha384() throws Exception {
        if (ecSupport) {
            test_xmldsig11("signature-enveloping-p256_sha384", "oracle");
        }
    }

    @Test
    void test_enveloping_p256_sha512() throws Exception {
        if (ecSupport) {
            test_xmldsig11("signature-enveloping-p256_sha512", "oracle");
        }
    }

    @Test
    void test_enveloping_p384_sha1() throws Exception {
        if (ecSupport) {
            test_xmldsig11("signature-enveloping-p384_sha1", "oracle");
        }
    }

    @Test
    void test_enveloping_p384_sha256() throws Exception {
        if (ecSupport) {
            test_xmldsig11("signature-enveloping-p384_sha256", "oracle");
        }
    }

    @Test
    void test_enveloping_p384_sha384() throws Exception {
        if (ecSupport) {
            test_xmldsig11("signature-enveloping-p384_sha384", "oracle");
        }
    }

    @Test
    void test_enveloping_p384_sha512() throws Exception {
        if (ecSupport) {
            test_xmldsig11("signature-enveloping-p384_sha512", "oracle");
        }
    }

    @Test
    void test_enveloping_p521_sha1() throws Exception {
        if (ecSupport) {
            test_xmldsig11("signature-enveloping-p521_sha1", "oracle");
        }
    }

    @Test
    void test_enveloping_p521_sha256() throws Exception {
        if (ecSupport) {
            test_xmldsig11("signature-enveloping-p521_sha256", "oracle");
        }
    }

    @Test
    void test_enveloping_p521_sha384() throws Exception {
        if (ecSupport) {
            test_xmldsig11("signature-enveloping-p521_sha384", "oracle");
        }
    }

    @Test
    void test_enveloping_p521_sha512() throws Exception {
        if (ecSupport) {
            test_xmldsig11("signature-enveloping-p521_sha512", "oracle");
        }
    }

    @Test
    void test_enveloping_rsa_sha256() throws Exception {
        test_xmldsig11("signature-enveloping-rsa-sha256", "oracle");
    }

    @Test
    void test_enveloping_rsa_sha384() throws Exception {
        test_xmldsig11("signature-enveloping-rsa_sha384", "oracle");
    }

    @Test
    void test_enveloping_rsa_sha512() throws Exception {
        test_xmldsig11("signature-enveloping-rsa_sha512", "oracle");
    }

    @Test
    void test_enveloping_sha256_rsa_sha256() throws Exception {
        test_xmldsig11("signature-enveloping-sha256-rsa-sha256", "oracle");
    }

    @Test
    void test_enveloping_sha384_rsa_sha256() throws Exception {
        test_xmldsig11("signature-enveloping-sha384-rsa_sha256", "oracle");
    }

    @Test
    void test_enveloping_sha512_rsa_sha256() throws Exception {
        test_xmldsig11("signature-enveloping-sha512-rsa_sha256", "oracle");
    }

    @Test
    void test_enveloping_hmac_sha256() throws Exception {
        test_xmldsig11("signature-enveloping-hmac-sha256", sks, "oracle");
    }

    @Test
    void test_enveloping_hmac_sha384() throws Exception {
        test_xmldsig11("signature-enveloping-hmac-sha384", sks, "oracle");
    }

    @Test
    void test_enveloping_hmac_sha512() throws Exception {
        test_xmldsig11("signature-enveloping-hmac-sha512", sks, "oracle");
    }

    private void test_xmldsig11(String test, String vendor) throws Exception {
        String file = vendor + File.separator + test + ".xml";
        // System.out.println("Validating " + file);
        boolean coreValidity = validator.validate(file, kvks);
        assertTrue(coreValidity, file + " failed core validation");
    }

    private void test_xmldsig11(String test, KeySelector ks, String vendor)
        throws Exception {
        String file = vendor + File.separator + test + ".xml";
        // System.out.println("Validating " + file);
        boolean coreValidity = validator.validate(file, ks);
        assertTrue(coreValidity, file + " failed core validation");
    }
}