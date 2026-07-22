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
package org.apache.xml.security.test.stax.resourceResolvers;

import org.apache.xml.security.stax.ext.ResourceResolver;
import org.apache.xml.security.stax.impl.resourceResolvers.ResolverHttp;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Unit tests for the scheme-filtering logic in {@link ResolverHttp#canResolve}.
 *
 * ResolverHttp must only accept http: and https: URIs and must never resolve
 * file:, ftp:, or other protocols, which would enable SSRF / local-file
 * disclosure attacks.
 */
class ResolverHttpTest {

    static {
        org.apache.xml.security.Init.init();
    }

    // -------------------------------------------------------------------------
    // Accepted schemes
    // -------------------------------------------------------------------------

    @Test
    void testHttpUriIsAccepted() {
        ResolverHttp resolver = new ResolverHttp();
        assertNotNull(resolver.canResolve("http://example.com/resource.xml", null),
            "http: URI must be accepted");
    }

    @Test
    void testHttpsUriIsAccepted() {
        ResolverHttp resolver = new ResolverHttp();
        assertNotNull(resolver.canResolve("https://example.com/resource.xml", null),
            "https: URI must be accepted");
    }

    @Test
    void testRelativeUriWithHttpBaseUriIsAccepted() {
        ResolverHttp resolver = new ResolverHttp();
        assertNotNull(resolver.canResolve("resource.xml", "http://example.com/docs/"),
            "A relative uri combined with an http: baseURI must be accepted");
    }

    @Test
    void testRelativeUriWithHttpsBaseUriIsAccepted() {
        ResolverHttp resolver = new ResolverHttp();
        assertNotNull(resolver.canResolve("resource.xml", "https://example.com/docs/"),
            "A relative uri combined with an https: baseURI must be accepted");
    }

    // -------------------------------------------------------------------------
    // Rejected schemes — non-HTTP protocols must never be resolved
    // -------------------------------------------------------------------------

    @Test
    void testFileUriIsRejected() {
        ResolverHttp resolver = new ResolverHttp();
        assertNull(resolver.canResolve("file:///etc/passwd", null),
            "file: URI must be rejected to prevent local-file disclosure");
    }

    @Test
    void testFileUriWithHttpBaseUriIsRejected() {
        ResolverHttp resolver = new ResolverHttp();
        // Even if baseURI is http:, an explicit file: uri must not be resolved
        // by this resolver (and should not match the http[s] pattern).
        assertNull(resolver.canResolve("file:///etc/passwd", "http://example.com/"),
            "file: URI must be rejected even when baseURI is http:");
    }

    @Test
    void testFtpUriIsRejected() {
        ResolverHttp resolver = new ResolverHttp();
        assertNull(resolver.canResolve("ftp://attacker.com/file.xml", null),
            "ftp: URI must be rejected");
    }

    @Test
    void testFtpUriWithHttpBaseUriIsRejected() {
        ResolverHttp resolver = new ResolverHttp();
        assertNull(resolver.canResolve("ftp://attacker.com/file.xml", "http://example.com/"),
            "ftp: URI must be rejected even when baseURI is http:");
    }

    @Test
    void testJarUriIsRejected() {
        ResolverHttp resolver = new ResolverHttp();
        assertNull(resolver.canResolve("jar:file:///app.jar!/META-INF/resource.xml", null),
            "jar: URI must be rejected");
    }

    // -------------------------------------------------------------------------
    // Null / empty URI handling
    // -------------------------------------------------------------------------

    @Test
    void testNullUriWithNullBaseUriIsRejected() {
        ResolverHttp resolver = new ResolverHttp();
        assertNull(resolver.canResolve(null, null),
            "null URI must always be rejected");
    }

    @Test
    void testNullUriWithHttpBaseUriIsRejected() {
        ResolverHttp resolver = new ResolverHttp();
        // canResolve must return null when uri is null regardless of baseURI
        assertNull(resolver.canResolve(null, "http://example.com/"),
            "null URI must be rejected even with a valid http: baseURI");
    }

    @Test
    void testRelativeUriWithNullBaseUriIsRejected() {
        ResolverHttp resolver = new ResolverHttp();
        assertNull(resolver.canResolve("resource.xml", null),
            "A relative URI with no baseURI cannot be resolved as http");
    }

    @Test
    void testRelativeUriWithFileBaseUriIsRejected() {
        ResolverHttp resolver = new ResolverHttp();
        assertNull(resolver.canResolve("resource.xml", "file:///var/app/"),
            "A relative URI with a file: baseURI must not be accepted by ResolverHttp");
    }

    // -------------------------------------------------------------------------
    // newInstance / isSameDocumentReference
    // -------------------------------------------------------------------------

    @Test
    void testNewInstanceReturnsResolverHttp() {
        ResolverHttp resolver = new ResolverHttp();
        ResourceResolver instance = resolver.newInstance("https://example.com/resource.xml", null);
        assertInstanceOf(ResolverHttp.class, instance,
            "newInstance must return a ResolverHttp");
    }

    @Test
    void testIsSameDocumentReferenceIsFalse() {
        ResolverHttp resolver = new ResolverHttp("https://example.com/resource.xml", null);
        org.junit.jupiter.api.Assertions.assertFalse(resolver.isSameDocumentReference(),
            "ResolverHttp always resolves external (non-same-document) references");
    }
}
