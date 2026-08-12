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

import java.util.HashMap;
import java.util.Map;

import org.apache.xml.security.Init;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.implementations.ResolverDirectHTTP;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;


class ResolverDirectHTTPTest {

    //change these properties to match your environment
    private static final String url = "http://www.apache.org";
    private static final String proxyHost = "127.0.0.1";
    private static final String proxyPort = "3128";
    private static final String proxyUsername = "proxyUser";
    private static final String proxyPassword = "proxyPass";
    private static final String serverUsername = "serverUser";
    private static final String serverPassword = "serverPass";

    @BeforeEach
    public void setUp() {
        Init.init();
    }

    @Test
    @Disabled
    void testProxyAuth() throws Exception {
        Document doc = TestUtils.newDocument();
        Attr uri = doc.createAttribute("URI");
        uri.setNodeValue(url);

        ResolverDirectHTTP resolverDirectHTTP = new ResolverDirectHTTP();
        Map<String, String> resolverProperties = new HashMap<>();
        resolverProperties.put("http.proxy.host",proxyHost);
        resolverProperties.put("http.proxy.port", proxyPort);
        resolverProperties.put("http.proxy.username", proxyUsername);
        resolverProperties.put("http.proxy.password", proxyPassword);
        ResourceResolverContext context =
            new ResourceResolverContext(uri, url, true, resolverProperties);
        resolverDirectHTTP.engineResolveURI(context);
    }

    @Test
    @Disabled
    void testProxyAuthWithWrongPassword() throws Exception {
        Document doc = TestUtils.newDocument();
        Attr uri = doc.createAttribute("URI");
        uri.setNodeValue(url);

        ResolverDirectHTTP resolverDirectHTTP = new ResolverDirectHTTP();
        Map<String, String> resolverProperties = new HashMap<>();
        resolverProperties.put("http.proxy.host",proxyHost);
        resolverProperties.put("http.proxy.port", proxyPort);
        resolverProperties.put("http.proxy.username", proxyUsername);
        resolverProperties.put("http.proxy.password", "wrongPassword");
        ResourceResolverContext context =
            new ResourceResolverContext(uri, url, true, resolverProperties);
        try {
            resolverDirectHTTP.engineResolveURI(context);
            fail("Expected ResourceResolverException");
        } catch (ResourceResolverException e) {
            assertEquals("Server returned HTTP response code: 407 for URL: " + url, e.getMessage());
        }
    }

    @Test
    @Disabled
    void testServerAuth() throws Exception {
        Document doc = TestUtils.newDocument();
        Attr uri = doc.createAttribute("URI");
        uri.setNodeValue(url);

        ResolverDirectHTTP resolverDirectHTTP = new ResolverDirectHTTP();
        Map<String, String> resolverProperties = new HashMap<>();
        resolverProperties.put("http.basic.username", serverUsername);
        resolverProperties.put("http.basic.password", serverPassword);
        ResourceResolverContext context =
            new ResourceResolverContext(uri, url, true, resolverProperties);
        resolverDirectHTTP.engineResolveURI(context);
    }

    @Test
    @Disabled
    void testServerAuthWithWrongPassword() throws Exception {
        Document doc = TestUtils.newDocument();
        Attr uri = doc.createAttribute("URI");
        uri.setNodeValue(url);

        ResolverDirectHTTP resolverDirectHTTP = new ResolverDirectHTTP();
        Map<String, String> resolverProperties = new HashMap<>();
        resolverProperties.put("http.basic.username", serverUsername);
        resolverProperties.put("http.basic.password", "wrongPassword");
        ResourceResolverContext context =
            new ResourceResolverContext(uri, url, true, resolverProperties);
        try {
            resolverDirectHTTP.engineResolveURI(context);
            fail("Expected ResourceResolverException");
        } catch (ResourceResolverException e) {
            assertEquals("Server returned HTTP response code: 401 for URL: " + url, e.getMessage());
        }
    }

    @Test
    @Disabled
    void testProxyAndServerAuth() throws Exception {
        Document doc = TestUtils.newDocument();
        Attr uri = doc.createAttribute("URI");
        uri.setNodeValue(url);

        ResolverDirectHTTP resolverDirectHTTP = new ResolverDirectHTTP();
        Map<String, String> resolverProperties = new HashMap<>();
        resolverProperties.put("http.proxy.host",proxyHost);
        resolverProperties.put("http.proxy.port", proxyPort);
        resolverProperties.put("http.proxy.username", proxyUsername);
        resolverProperties.put("http.proxy.password", proxyPassword);
        resolverProperties.put("http.basic.username", serverUsername);
        resolverProperties.put("http.basic.password", serverPassword);
        ResourceResolverContext context =
            new ResourceResolverContext(uri, url, true, resolverProperties);
        resolverDirectHTTP.engineResolveURI(context);
    }
}

class ResolverDirectHTTPSchemeFilterTest {

    static {
        org.apache.xml.security.Init.init();
    }

    private static ResourceResolverContext makeContext(String uri, String baseUri) throws Exception {
        Document doc = TestUtils.newDocument();
        Attr attr = doc.createAttribute("URI");
        attr.setValue(uri);
        return new ResourceResolverContext(attr, baseUri, false);
    }

    // -------------------------------------------------------------------------
    // engineCanResolveURI — accepted schemes
    // -------------------------------------------------------------------------

    @Test
    void testHttpUriIsAccepted() throws Exception {
        ResolverDirectHTTP resolver = new ResolverDirectHTTP();
        assertTrue(resolver.engineCanResolveURI(makeContext("http://example.com/resource.xml", null)),
            "http: URI must be accepted");
    }

    @Test
    void testHttpsUriIsAccepted() throws Exception {
        ResolverDirectHTTP resolver = new ResolverDirectHTTP();
        assertTrue(resolver.engineCanResolveURI(makeContext("https://example.com/resource.xml", null)),
            "https: URI must be accepted");
    }

    @Test
    void testRelativeUriWithHttpBaseUriIsAccepted() throws Exception {
        ResolverDirectHTTP resolver = new ResolverDirectHTTP();
        assertTrue(resolver.engineCanResolveURI(makeContext("resource.xml", "http://example.com/docs/")),
            "A relative URI combined with an http: baseUri must be accepted");
    }

    @Test
    void testRelativeUriWithHttpsBaseUriIsAccepted() throws Exception {
        ResolverDirectHTTP resolver = new ResolverDirectHTTP();
        assertTrue(resolver.engineCanResolveURI(makeContext("resource.xml", "https://example.com/docs/")),
            "A relative URI combined with an https: baseUri must be accepted");
    }

    // -------------------------------------------------------------------------
    // engineCanResolveURI — rejected schemes
    // -------------------------------------------------------------------------

    @Test
    void testFileUriIsRejected() throws Exception {
        ResolverDirectHTTP resolver = new ResolverDirectHTTP();
        assertFalse(resolver.engineCanResolveURI(makeContext("file:///etc/passwd", null)),
            "file: URI must be rejected to prevent local-file disclosure");
    }

    @Test
    void testFileUriWithHttpBaseUriIsRejected() throws Exception {
        ResolverDirectHTTP resolver = new ResolverDirectHTTP();
        assertFalse(resolver.engineCanResolveURI(makeContext("file:///etc/passwd", "http://example.com/")),
            "file: URI must be rejected even when baseUri is http:");
    }

    @Test
    void testFtpUriIsRejected() throws Exception {
        ResolverDirectHTTP resolver = new ResolverDirectHTTP();
        assertFalse(resolver.engineCanResolveURI(makeContext("ftp://attacker.com/file.xml", null)),
            "ftp: URI must be rejected");
    }

    @Test
    void testFtpUriWithHttpBaseUriIsRejected() throws Exception {
        ResolverDirectHTTP resolver = new ResolverDirectHTTP();
        assertFalse(resolver.engineCanResolveURI(makeContext("ftp://attacker.com/file.xml", "http://example.com/")),
            "ftp: URI must be rejected even when baseUri is http:");
    }

    @Test
    void testJarUriIsRejected() throws Exception {
        ResolverDirectHTTP resolver = new ResolverDirectHTTP();
        assertFalse(resolver.engineCanResolveURI(makeContext("jar:file:///app.jar!/META-INF/resource.xml", null)),
            "jar: URI must be rejected");
    }

    @Test
    void testNullUriIsRejected() throws Exception {
        Document doc = TestUtils.newDocument();
        Attr attr = doc.createAttribute("URI");
        // leave value empty — uriToResolve will be ""
        ResourceResolverContext ctx = new ResourceResolverContext(attr, null, false);
        ResolverDirectHTTP resolver = new ResolverDirectHTTP();
        assertFalse(resolver.engineCanResolveURI(ctx),
            "Empty URI must be rejected");
    }

    @Test
    void testRelativeUriWithFileBaseUriIsRejected() throws Exception {
        ResolverDirectHTTP resolver = new ResolverDirectHTTP();
        assertFalse(resolver.engineCanResolveURI(makeContext("resource.xml", "file:///var/app/")),
            "A relative URI with a file: baseUri must not be accepted by ResolverDirectHTTP");
    }

    // -------------------------------------------------------------------------
    // engineResolveURI — defense-in-depth scheme validation
    // -------------------------------------------------------------------------

    @Test
    void testEngineResolveURIWithFileSchemeThrows() throws Exception {
        ResolverDirectHTTP resolver = new ResolverDirectHTTP();
        ResourceResolverContext ctx = makeContext("file:///etc/passwd", null);
        assertThrows(ResourceResolverException.class, () -> resolver.engineResolveURI(ctx),
            "engineResolveURI must throw when the resolved URI scheme is not http/https");
    }

    @Test
    void testEngineResolveURIWithFtpSchemeThrows() throws Exception {
        ResolverDirectHTTP resolver = new ResolverDirectHTTP();
        ResourceResolverContext ctx = makeContext("ftp://attacker.com/file.xml", null);
        assertThrows(ResourceResolverException.class, () -> resolver.engineResolveURI(ctx),
            "engineResolveURI must throw when the resolved URI scheme is ftp");
    }
}
