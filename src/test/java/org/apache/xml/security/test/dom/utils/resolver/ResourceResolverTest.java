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
public class ResourceResolverTest {

    static org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger
            (ResourceResolverTest.class);

    static {
        org.apache.xml.security.Init.init();
    }

    /**
     * Tests registering a custom resolver implementation.
     */
    @Test
    public void testCustomResolver() throws Exception {
        final String className =
            "org.apache.xml.security.test.dom.utils.resolver.OfflineResolver";
        ResourceResolver.registerAtStart(className);
        final Document doc = TestUtils.newDocument();
        final Attr uriAttr = doc.createAttribute("URI");
        uriAttr.setValue("http://www.apache.org");

        ResourceResolverContext resolverContext =
            new ResourceResolverContext(uriAttr, "http://www.apache.org", true);
        try {
            uriAttr.setValue("http://xmldsig.pothole.com/xml-stylesheet.txt");
            resolverContext = new ResourceResolverContext(uriAttr, null, true);
            assertNotNull(ResourceResolver.resolve(resolverContext));
        } catch (final Exception e) {
            fail(uriAttr.getValue()
                + " should be resolvable by the OfflineResolver");
        }
        try {
            uriAttr.setValue("http://www.apache.org");
            resolverContext = new ResourceResolverContext(uriAttr, null, true);
            ResourceResolver.resolve(resolverContext);
            fail(uriAttr.getValue() + " should not be resolvable by the OfflineResolver");
        } catch (final Exception e) {
            //
        }
    }

    @Test
    public void testLocalFileWithEmptyBaseURI() throws Exception {
        final Document doc = TestUtils.newDocument();
        final Attr uriAttr = doc.createAttribute("URI");
        final String file = resolveFile("pom.xml").toURI().toString();
        uriAttr.setValue(file);

        ResourceResolver.register(new ResolverLocalFilesystem(), false);
        ResourceResolverContext resolverContext =
            new ResourceResolverContext(uriAttr, file, false);
        try {
            resolverContext = new ResourceResolverContext(uriAttr, "", false);
            assertNotNull(ResourceResolver.resolve(resolverContext));
        } catch (final Exception e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testIsSafeURIToResolveFile() throws Exception {
        final Document doc = TestUtils.newDocument();
        final Attr uriAttr = doc.createAttribute("URI");
        final String file = resolveFile("pom.xml").toURI().toString();
        uriAttr.setValue(file);

        final ResourceResolverContext resolverContext =
                new ResourceResolverContext(uriAttr, null, false);
        assertFalse(resolverContext.isURISafeToResolve());
    }

    @Test
    public void testIsSafeURIToResolveFileBaseURI() throws Exception {
        final Document doc = TestUtils.newDocument();
        final Attr uriAttr = doc.createAttribute("URI");
        final String file = resolveFile("pom.xml").toURI().toString();
        uriAttr.setValue("xyz");

        final ResourceResolverContext resolverContext =
                new ResourceResolverContext(uriAttr, file, false);
        assertFalse(resolverContext.isURISafeToResolve());
    }

    @Test
    public void testIsSafeURIToResolveHTTP() throws Exception {
        final Document doc = TestUtils.newDocument();
        final Attr uriAttr = doc.createAttribute("URI");
        uriAttr.setValue("http://www.apache.org");

        final ResourceResolverContext resolverContext =
                new ResourceResolverContext(uriAttr, null, false);
        assertFalse(resolverContext.isURISafeToResolve());
    }

    @Test
    public void testIsSafeURIToResolveHTTPBaseURI() throws Exception {
        final Document doc = TestUtils.newDocument();
        final Attr uriAttr = doc.createAttribute("URI");
        uriAttr.setValue("xyz");

        final ResourceResolverContext resolverContext =
                new ResourceResolverContext(uriAttr, "http://www.apache.org", false);
        assertFalse(resolverContext.isURISafeToResolve());
    }

    @Test
    public void testIsSafeURIToResolveLocalReference() throws Exception {
        final Document doc = TestUtils.newDocument();
        final Attr uriAttr = doc.createAttribute("URI");
        uriAttr.setValue("#1234");

        final ResourceResolverContext resolverContext =
                new ResourceResolverContext(uriAttr, null, false);
        assertTrue(resolverContext.isURISafeToResolve());
    }
}