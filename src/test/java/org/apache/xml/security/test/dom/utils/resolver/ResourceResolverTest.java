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
package org.apache.xml.security.test.dom.utils.resolver;


import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.implementations.ResolverLocalFilesystem;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Unit test for {@link org.apache.xml.security.utils.resolver.ResourceResolver}
 *
 */
class ResourceResolverTest {

    static {
        org.apache.xml.security.Init.init();
    }

    /**
     * Tests registering a custom resolver implementation.
     */
    @Test
    void testCustomResolver() throws Exception {
        String className =
            "org.apache.xml.security.test.dom.utils.resolver.OfflineResolver";
        ResourceResolver.registerAtStart(className);
        Document doc = TestUtils.newDocument();
        Attr uriAttr = doc.createAttribute("URI");
        uriAttr.setValue("http://www.apache.org");

        ResourceResolverContext resolverContext =
            new ResourceResolverContext(uriAttr, "http://www.apache.org", true);
        try {
            uriAttr.setValue("http://xmldsig.pothole.com/xml-stylesheet.txt");
            resolverContext = new ResourceResolverContext(uriAttr, null, true);
            assertNotNull(ResourceResolver.resolve(resolverContext));
        } catch (Exception e) {
            fail(uriAttr.getValue()
                + " should be resolvable by the OfflineResolver");
        }
        try {
            uriAttr.setValue("http://www.apache.org");
            resolverContext = new ResourceResolverContext(uriAttr, null, true);
            ResourceResolver.resolve(resolverContext);
            fail(uriAttr.getValue() + " should not be resolvable by the OfflineResolver");
        } catch (Exception e) {
            //
        }
    }

    @Test
    void testLocalFileWithEmptyBaseURI() throws Exception {
        Document doc = TestUtils.newDocument();
        Attr uriAttr = doc.createAttribute("URI");
        String file = resolveFile("pom.xml").toURI().toString();
        uriAttr.setValue(file);

        ResourceResolver.register(new ResolverLocalFilesystem(), false);
        ResourceResolverContext resolverContext =
            new ResourceResolverContext(uriAttr, file, false);
        try {
            resolverContext = new ResourceResolverContext(uriAttr, "", false);
            assertNotNull(ResourceResolver.resolve(resolverContext));
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    @Test
    void testIsSafeURIToResolveFile() throws Exception {
        Document doc = TestUtils.newDocument();
        Attr uriAttr = doc.createAttribute("URI");
        String file = resolveFile("pom.xml").toURI().toString();
        uriAttr.setValue(file);

        ResourceResolverContext resolverContext =
                new ResourceResolverContext(uriAttr, null, false);
        assertFalse(resolverContext.isURISafeToResolve());
    }

    @Test
    void testIsSafeURIToResolveFileBaseURI() throws Exception {
        Document doc = TestUtils.newDocument();
        Attr uriAttr = doc.createAttribute("URI");
        String file = resolveFile("pom.xml").toURI().toString();
        uriAttr.setValue("xyz");

        ResourceResolverContext resolverContext =
                new ResourceResolverContext(uriAttr, file, false);
        assertFalse(resolverContext.isURISafeToResolve());
    }

    @Test
    void testIsSafeURIToResolveHTTP() throws Exception {
        Document doc = TestUtils.newDocument();
        Attr uriAttr = doc.createAttribute("URI");
        uriAttr.setValue("http://www.apache.org");

        ResourceResolverContext resolverContext =
                new ResourceResolverContext(uriAttr, null, false);
        assertFalse(resolverContext.isURISafeToResolve());
    }

    @Test
    void testIsSafeURIToResolveHTTPBaseURI() throws Exception {
        Document doc = TestUtils.newDocument();
        Attr uriAttr = doc.createAttribute("URI");
        uriAttr.setValue("xyz");

        ResourceResolverContext resolverContext =
                new ResourceResolverContext(uriAttr, "http://www.apache.org", false);
        assertFalse(resolverContext.isURISafeToResolve());
    }

    @Test
    void testIsSafeURIToResolveLocalReference() throws Exception {
        Document doc = TestUtils.newDocument();
        Attr uriAttr = doc.createAttribute("URI");
        uriAttr.setValue("#1234");

        ResourceResolverContext resolverContext =
                new ResourceResolverContext(uriAttr, null, false);
        assertTrue(resolverContext.isURISafeToResolve());
    }
}