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
package org.apache.xml.security.test.dom.secure_val;


import java.io.File;

import org.apache.xml.security.signature.Manifest;
import org.apache.xml.security.signature.MissingResourceFailureException;
import org.apache.xml.security.test.dom.interop.InteropTestBase;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xml.security.utils.resolver.implementations.ResolverLocalFilesystem;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * This is a test for a forbidden Reference algorithm
 */
class ForbiddenReferenceTest extends InteropTestBase {

    static {
        org.apache.xml.security.Init.init();
    }

    @Test
    void testLocalFilesystem() throws Exception {
        try {
            readAndVerifyManifest("signature.xml");
            fail("Failure expected when secure validation is enabled");
        } catch (MissingResourceFailureException ex) {
            assertTrue(ex.getMessage().contains("The Reference for URI"));
        }

        // Now it should work as we have added the local file resolver
        ResourceResolver.register(new ResolverLocalFilesystem(), false);
        boolean success = readAndVerifyManifest("signature.xml");
        assertTrue(success);
    }


    private boolean readAndVerifyManifest(String file) throws Exception {
        File f = resolveFile("src", "test", "resources", "interop", "c14n", "Y3", file);
        org.w3c.dom.Document doc = XMLUtils.read(f, false);

        Element manifestElement = (Element) doc
            .getElementsByTagNameNS(Constants.SignatureSpecNS, Constants._TAG_SIGNEDINFO).item(0);
        Manifest manifest = new Manifest(manifestElement, f.toURI().toURL().toString(), true);
        return manifest.verifyReferences();
    }

}