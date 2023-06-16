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

import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.dom.DOMValidateContext;

import org.apache.xml.security.test.javax.xml.crypto.KeySelectors;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xml.security.utils.resolver.implementations.ResolverLocalFilesystem;
import org.junit.jupiter.api.Test;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * This is a test for a forbidden Reference algorithm.
 */
class JSRForbiddenReferenceTest {

    private final SignatureValidator validator;
    private final File dir;

    static {
        Security.insertProviderAt(new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    public JSRForbiddenReferenceTest() {
        dir = resolveFile("src", "test", "resources", "org", "apache", "xml", "security", "test", "javax", "xml", "crypto", "dsig");
        validator = new SignatureValidator(dir);
    }


    @Test
    void testLocalFilesystem() throws Exception {
        String file = "signature-external-c14n-xmlatrs.xml";

        DOMValidateContext vc =
            validator.getValidateContext(
                file, new KeySelectors.SecretKeySelector("secret".getBytes(StandardCharsets.US_ASCII))
            );

        try {
            validator.validate(vc);
            fail("Failure expected by default");
        } catch (XMLSignatureException ex) {
            assertTrue(ex.getMessage().contains("URIReferenceException"));
        }

        // Now it should work as we have added the local file resolver
        ResourceResolver.register(new ResolverLocalFilesystem(), false);
        assertTrue(validator.validate(vc));
    }

}