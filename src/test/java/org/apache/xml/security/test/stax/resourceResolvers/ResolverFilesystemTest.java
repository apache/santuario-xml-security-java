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

import org.apache.xml.security.stax.impl.resourceResolvers.ResolverFilesystem;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Tests for the scheme-checking logic in ResolverFilesystem.
 *
 * The fix requires that at least one of uri / baseURI starts with "file:"
 * AND neither carries a different explicit scheme. This prevents a live-SSRF
 * attack where an https: (or http:, ftp:, etc.) uri was incorrectly accepted
 * solely because baseURI happened to start with "file:".
 */
class ResolverFilesystemTest {

    static {
        org.apache.xml.security.Init.init();
    }

    // -------------------------------------------------------------------------
    // canResolve() — scheme bypass tests
    // -------------------------------------------------------------------------

    /**
     * Baseline: a plain file: URI with a file: baseURI is accepted (expected).
     */
    @Test
    void testFileUriWithFileBaseUriIsAccepted() {
        ResolverFilesystem resolver = new ResolverFilesystem();
        assertNotNull(resolver.canResolve("file:///etc/hosts", "file:///var/app/"),
            "A file: URI with a file: baseURI should be accepted");
    }

    /**
     * FIX: https: uri must be rejected even when baseURI is file:.
     */
    @Test
    void testHttpsUriIsRejectedWhenBaseUriIsFile() {
        ResolverFilesystem resolver = new ResolverFilesystem();
        assertNull(resolver.canResolve("https://attacker.com/payload", "file:///var/app/"),
            "FIX VERIFIED: https: uri must be rejected even with a file: baseURI");
    }

    /**
     * FIX: http: uri must also be rejected when baseURI is file:.
     */
    @Test
    void testHttpUriIsRejectedWhenBaseUriIsFile() {
        ResolverFilesystem resolver = new ResolverFilesystem();
        assertNull(resolver.canResolve("http://attacker.com/payload", "file:///var/app/"),
            "FIX VERIFIED: http: uri must be rejected even with a file: baseURI");
    }

    /**
     * FIX: ftp: and other non-file schemes must also be rejected.
     */
    @Test
    void testFtpUriIsRejectedWhenBaseUriIsFile() {
        ResolverFilesystem resolver = new ResolverFilesystem();
        assertNull(resolver.canResolve("ftp://attacker.com/file.xml", "file:///var/app/"),
            "FIX VERIFIED: ftp: uri must be rejected even with a file: baseURI");
    }

    /**
     * A relative uri (no scheme) combined with a file: baseURI is accepted —
     * this is the primary legitimate use case.
     */
    @Test
    void testRelativeUriWithFileBaseUriIsAccepted() {
        ResolverFilesystem resolver = new ResolverFilesystem();
        assertNotNull(resolver.canResolve("subdoc.xml", "file:///var/app/"),
            "A relative uri with a file: baseURI must be accepted");
    }

    /**
     * VULN: URI.resolve() returns an absolute uri unchanged, so the final URL
     * opened by getInputStreamFromExternalReference() will be the attacker's
     * https: URL — a live SSRF. Demonstrate that resolve() does not anchor
     * the result under the file: base.
     */
    @Test
    void testUriResolveLeavesAbsoluteUriUnchanged() throws Exception {
        java.net.URI base     = new java.net.URI("file:///var/app/");
        java.net.URI absolute = new java.net.URI("https://attacker.com/payload");

        java.net.URI resolved = base.resolve(absolute);

        assertFalse("file".equals(resolved.getScheme()),
            "VULN CONFIRMED: resolved URI scheme is '" + resolved.getScheme()
            + "', not 'file' — toURL().openStream() will make an outbound HTTPS request");
    }

    // -------------------------------------------------------------------------
    // Sanity checks — cases that should correctly be rejected
    // -------------------------------------------------------------------------

    /**
     * An https: URI with no baseURI is correctly rejected.
     */
    @Test
    void testHttpsUriWithNullBaseUriIsRejected() {
        ResolverFilesystem resolver = new ResolverFilesystem();
        assertNull(resolver.canResolve("https://attacker.com/payload", null),
            "https: URI with null baseURI should not be accepted");
    }

    /**
     * An https: URI with an https: baseURI is correctly rejected.
     */
    @Test
    void testHttpsUriWithHttpsBaseUriIsRejected() {
        ResolverFilesystem resolver = new ResolverFilesystem();
        assertNull(resolver.canResolve("https://attacker.com/payload", "https://victim.com/"),
            "https: URI with https: baseURI should not be accepted");
    }

    /**
     * A null URI is correctly rejected.
     */
    @Test
    void testNullUriIsRejected() {
        ResolverFilesystem resolver = new ResolverFilesystem();
        assertNull(resolver.canResolve(null, "file:///var/app/"),
            "null URI should always be rejected");
    }

}
