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
import org.junit.jupiter.api.Test;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * This is a testcase to validate the "merlin-xpath-filter2-three" testcases
 * under data/vectors/ie/baltimore/merlin-examples directory
 *
 */
class BaltimoreXPathFilter2ThreeTest {

    private final SignatureValidator validator;

    static {
        Security.insertProviderAt(new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    public BaltimoreXPathFilter2ThreeTest() {
        File file = resolveFile("src", "test", "resources", "interop", "xfilter2", "merlin-xpath-filter2-three");
        validator = new SignatureValidator(file);
    }

    @Test
    void testSignSpec() throws Exception {
        String file = "sign-spec.xml";

        boolean coreValidity = validator.validate(file,
                    new KeySelectors.KeyValueKeySelector());
        assertTrue(coreValidity, "Signature failed core validation#1");

        coreValidity = validator.validate(file,
                    new KeySelectors.RawX509KeySelector());
        assertTrue(coreValidity, "Signature failed core validation#2");
    }

    @Test
    void testSignXfdl() throws Exception {
        String file = "sign-xfdl.xml";

        boolean coreValidity = validator.validate(file,
                    new KeySelectors.KeyValueKeySelector());
        assertTrue(coreValidity, "Signature failed core validation#1");

        coreValidity = validator.validate(file,
                    new KeySelectors.RawX509KeySelector());
        assertTrue(coreValidity, "Signature failed core validation#2");
    }

}