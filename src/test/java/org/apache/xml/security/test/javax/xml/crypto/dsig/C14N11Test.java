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

import javax.xml.crypto.KeySelector;

import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.javax.xml.crypto.KeySelectors;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xml.security.utils.resolver.implementations.ResolverLocalFilesystem;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * This is a testcase to validate all the W3C xmldsig C14N11 testcases.
 *
 */
class C14N11Test {

    private final SignatureValidator validator;
    private final File dir;
    private final KeySelector sks;
    private static String[] vendors = { "IAIK", "IBM", "ORCL", "SUN", "UPC" };

    static {
        Security.insertProviderAt
            (new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
        ResourceResolver.register(new ResolverLocalFilesystem(), false);
    }

    public C14N11Test() throws Exception {
        dir = XmlSecTestEnvironment.resolveFile("src", "test", "resources", "org", "w3c", "www", "interop", "xmldsig",
            "c14n11");
        validator = new SignatureValidator(dir);
        sks = new KeySelectors.SecretKeySelector("secret".getBytes(StandardCharsets.US_ASCII));
    }

    @Test
    void test_xmlid_1() throws Exception {
        test_c14n11("xmlid-1");
    }

    @Test
    void test_xmlid_2() throws Exception {
        test_c14n11("xmlid-2");
    }

    @Test
    void test_xmlspace_1() throws Exception {
        test_c14n11("xmlspace-1");
    }

    @Test
    void test_xmlspace_2() throws Exception {
        test_c14n11("xmlspace-2");
    }

    @Test
    void test_xmlspace_3() throws Exception {
        test_c14n11("xmlspace-3");
    }

    @Test
    void test_xmlspace_4() throws Exception {
        test_c14n11("xmlspace-4");
    }

    @Test
    void test_xmllang_1() throws Exception {
        test_c14n11("xmllang-1");
    }

    @Test
    void test_xmllang_2() throws Exception {
        test_c14n11("xmllang-2");
    }

    @Test
    void test_xmllang_3() throws Exception {
        test_c14n11("xmllang-3");
    }

    @Test
    void test_xmllang_4() throws Exception {
        test_c14n11("xmllang-4");
    }

    @Test
    void test_xmlbase_prop_1() throws Exception {
        test_c14n11("xmlbase-prop-1");
    }

    @Test
    void test_xmlbase_prop_2() throws Exception {
        test_c14n11("xmlbase-prop-2");
    }

    @Test
    void test_xmlbase_prop_3() throws Exception {
        test_c14n11("xmlbase-prop-3");
    }

    @Test
    void test_xmlbase_prop_4() throws Exception {
        test_c14n11("xmlbase-prop-4");
    }

    @Test
    void test_xmlbase_prop_5() throws Exception {
        test_c14n11("xmlbase-prop-5");
    }

    @Test
    void test_xmlbase_prop_6() throws Exception {
        test_c14n11("xmlbase-prop-6");
    }

    @Test
    void test_xmlbase_prop_7() throws Exception {
        test_c14n11("xmlbase-prop-7");
    }

    @Test
    void test_xmlbase_c14n11spec_102() throws Exception {
        String[] vendors = {"IAIK", "IBM", "ORCL", "SUN", "UPC"};
        test_c14n11("xmlbase-c14n11spec-102", vendors);
    }

    @Test
    void test_xmlbase_c14n11spec2_102() throws Exception {
        String[] vendors = {"IAIK", "IBM", "ORCL", "SUN"};
        test_c14n11("xmlbase-c14n11spec2-102", vendors);
    }

    @Test
    void test_xmlbase_c14n11spec3_103() throws Exception {
        String[] vendors = {"IAIK", "IBM", "ORCL", "SUN", "UPC"};
        test_c14n11("xmlbase-c14n11spec3-103", vendors);
    }

    private void test_c14n11(String test) throws Exception {
        for (String vendor : vendors) {
            String file = test + "-" + vendor + ".xml";
            // System.out.println("Validating " + file);
            boolean coreValidity = validator.validate(file, sks);
            assertTrue(coreValidity, file + " failed core validation");
        }
    }

    private void test_c14n11(String test, String[] vendors) throws Exception {
        for (String vendor : vendors) {
            String file = test + "-" + vendor + ".xml";
            // System.out.println("Validating " + file);
            boolean coreValidity = validator.validate(file, sks, null, false);
            assertTrue(coreValidity, file + " failed core validation");
        }
    }
}