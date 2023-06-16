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

import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.javax.xml.crypto.KeySelectors;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * This is a testcase to validate all "bdournaee"
 * testcases from RSA
 *
 */
public class ComRSASecurityTest {

    private final SignatureValidator validator;

    static {
        Security.insertProviderAt(new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    public ComRSASecurityTest() {
        File base = XmlSecTestEnvironment.resolveFile("src", "test", "resources", "com", "rsasecurity", "bdournaee");
        validator = new SignatureValidator(base);
    }


    @Test
    public void test_certj201_enveloping() throws Exception {
        String file = "certj201_enveloping.xml";

        boolean coreValidity = validator.validate(file, new KeySelectors.KeyValueKeySelector());
        assertTrue(coreValidity, "Signature failed core validation");
    }


    @Test
    public void test_certj201_enveloped() throws Exception {
        String file = "certj201_enveloped.xml";

        boolean coreValidity = validator.validate(file, new KeySelectors.KeyValueKeySelector());
        assertTrue(coreValidity, "Signature failed core validation");
    }

}