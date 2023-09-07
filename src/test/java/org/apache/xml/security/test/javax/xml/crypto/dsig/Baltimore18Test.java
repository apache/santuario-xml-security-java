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
import java.security.cert.CertificateException;

import javax.xml.crypto.KeySelector;
import javax.xml.crypto.URIDereferencer;

import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.javax.xml.crypto.KeySelectors;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * This is a testcase to validate all "merlin-xmldsig-eighteen"
 * testcases from Baltimore
 *
 */
class Baltimore18Test {

    private final File dir;
    private final KeySelector cks;
    private final URIDereferencer ud;

    static {
        Security.insertProviderAt
            (new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    public Baltimore18Test() throws CertificateException {
        dir = XmlSecTestEnvironment.resolveFile("src", "test", "resources", "ie", "baltimore", "merlin-examples",
            "merlin-xmldsig-eighteen");
        cks = new KeySelectors.CollectionKeySelector(dir);
        ud = new LocalHttpCacheURIDereferencer();
    }

    @Test
    void testSignatureKeyname() throws Exception {
        String file = "signature-keyname.xml";

        SignatureValidator validator = new SignatureValidator(dir);
        boolean coreValidity = validator.validate(file, cks, ud);
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void testSignatureRetrievalmethodRawx509crt() throws Exception {
        String file = "signature-retrievalmethod-rawx509crt.xml";

        SignatureValidator validator = new SignatureValidator(dir);
        boolean coreValidity = validator.validate(file, cks, ud);
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void testSignatureX509CrtCrl() throws Exception {
        String file = "signature-x509-crt-crl.xml";

        SignatureValidator validator = new SignatureValidator(dir);
        boolean coreValidity = validator.validate(file, cks, ud);
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void testSignatureX509Crt() throws Exception {
        String file = "signature-x509-crt.xml";

        SignatureValidator validator = new SignatureValidator(dir);
        boolean coreValidity = validator.validate(file, cks, ud);
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void testSignatureX509Is() throws Exception {
        String file = "signature-x509-is.xml";

        SignatureValidator validator = new SignatureValidator(dir);
        boolean coreValidity = validator.validate(file, cks, ud);
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void testSignatureX509Ski() throws Exception {
        String file = "signature-x509-ski.xml";

        SignatureValidator validator = new SignatureValidator(dir);
        boolean coreValidity = validator.validate(file, cks, ud);
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void testSignatureX509Sn() throws Exception {
        String file = "signature-x509-sn.xml";

        SignatureValidator validator = new SignatureValidator(dir);
        boolean coreValidity = validator.validate(file, cks, ud);
        assertTrue(coreValidity, "Signature failed core validation");
    }

}