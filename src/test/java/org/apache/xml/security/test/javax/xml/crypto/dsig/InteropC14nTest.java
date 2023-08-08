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
import java.security.Security;

import org.apache.xml.security.test.javax.xml.crypto.KeySelectors;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xml.security.utils.resolver.implementations.ResolverLocalFilesystem;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * This is a testcase to validate all "c14n" testcases
 * under data/vectors/interop directory
 *
 */
class InteropC14nTest {

    private SignatureValidator validator;
    private final File base;

    static {
        Security.insertProviderAt(new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
        ResourceResolver.register(new ResolverLocalFilesystem(), false);
    }

    public InteropC14nTest() {
        base = resolveFile("src", "test", "resources", "interop", "c14n");
    }

    @Test
    void test_y1_exc_signature() throws Exception {
        validator = new SignatureValidator(new File(base, "Y1"));
        String file = "exc-signature.xml";

        boolean coreValidity = validator.validate
            (file, new KeySelectors.KeyValueKeySelector());
        assertTrue(coreValidity, "Signature failed core validation");

    }

    /* COMMENTED OUT since this test requires MD5 support
    public void test_y2_signature_joseph_exc() throws Exception {
        validator = new SignatureValidator(new File(base, "Y2"));
        String file = "signature-joseph-exc.xml";

        boolean coreValidity = validator.validate
            (file, new KeySelectors.KeyValueKeySelector());
        assertTrue(coreValidity, "Signature failed core validation");
    }
    */

    @Test
    void test_y3_signature() throws Exception {
        validator = new SignatureValidator(new File(base, "Y3"));
        String file = "signature.xml";

        boolean coreValidity = validator.validate
            (file, new KeySelectors.KeyValueKeySelector());
        assertTrue(coreValidity, "Signature failed core validation#1");

        coreValidity = validator.validate
            (file, new KeySelectors.RawX509KeySelector());
        assertTrue(coreValidity, "Signature failed core validation#2");
    }

    @Test
    void test_y4_signature() throws Exception {
        validator = new SignatureValidator(new File(base, "Y4"));
        String file = "signature.xml";

        boolean coreValidity = validator.validate
            (file, new KeySelectors.KeyValueKeySelector());
        assertTrue(coreValidity, "Signature failed core validation#1");

        coreValidity = validator.validate
            (file, new KeySelectors.RawX509KeySelector());
        assertTrue(coreValidity, "Signature failed core validation#2");
    }

    @Test
    @Disabled
    void test_y5_signature() throws Exception {
        validator = new SignatureValidator(new File(base, "Y5"));
        String file = "signature.xml";

        boolean coreValidity = validator.validate
            (file, new KeySelectors.KeyValueKeySelector());
        assertTrue(coreValidity, "Signature failed core validation#1");

        coreValidity = validator.validate
            (file, new KeySelectors.RawX509KeySelector());
        assertTrue(coreValidity, "Signature failed core validation#2");
    }

    @Test
    @Disabled
    void test_y5_signatureCommented() throws Exception {
        validator = new SignatureValidator(new File(base, "Y5"));
        String file = "signatureCommented.xml";

        boolean coreValidity = validator.validate
            (file, new KeySelectors.KeyValueKeySelector());
        assertTrue(coreValidity, "Signature failed core validation#1");

        coreValidity = validator.validate
            (file, new KeySelectors.RawX509KeySelector());
        assertTrue(coreValidity, "Signature failed core validation#2");
    }

}