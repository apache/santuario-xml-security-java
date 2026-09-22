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
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.implementations.ResolverLocalFilesystem;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for the scheme-checking logic in ResolverLocalFilesystem.
 *
 * The fix requires that at least one of uriToResolve / baseUri starts with "file:"
 * AND neither carries a different explicit scheme. This prevents a resolver-hijacking
 * attack where an https: (or ftp:, etc.) uriToResolve was incorrectly accepted solely
 * because the baseUri happened to start with "file:".
 */
class ResolverLocalFilesystemTest {

    static {
        org.apache.xml.security.Init.init();
    }

    private static ResourceResolverContext makeContext(String uri, String baseUri) throws Exception {
        Document doc = TestUtils.newDocument();
        Attr attr = doc.createAttribute("URI");
        attr.setValue(uri);
        return new ResourceResolverContext(attr, baseUri, false);
    }

    /**
     * Baseline: a plain file: URI with a file: baseUri is accepted (expected behaviour).
     */
    @Test
    void testFileUriWithFileBaseUriIsAccepted() throws Exception {
        ResolverLocalFilesystem resolver = new ResolverLocalFilesystem();
        ResourceResolverContext ctx = makeContext("file:///etc/hosts", "file:///var/app/");
        assertTrue(resolver.engineCanResolveURI(ctx),
            "A file: URI with a file: baseUri should be accepted");
    }

    /**
     * FIX: an https: uriToResolve must be rejected even when baseUri is "file:".
     * Previously the resolver incorrectly claimed ownership of https: URIs solely
     * because baseUri started with "file:", allowing resolver hijacking.
     */
    @Test
    void testHttpsUriIsRejectedWhenBaseUriIsFile() throws Exception {
        ResolverLocalFilesystem resolver = new ResolverLocalFilesystem();
        ResourceResolverContext ctx = makeContext("https://attacker.com/payload", "file:///var/app/");

        assertFalse(resolver.engineCanResolveURI(ctx),
            "FIX VERIFIED: https: uriToResolve must be rejected even with a file: baseUri");
    }

    /**
     * FIX: any non-file explicit scheme in uriToResolve must be rejected,
     * regardless of baseUri.
     */
    @Test
    void testFtpUriIsRejectedWhenBaseUriIsFile() throws Exception {
        ResolverLocalFilesystem resolver = new ResolverLocalFilesystem();
        ResourceResolverContext ctx = makeContext("ftp://attacker.com/file.xml", "file:///var/app/");

        assertFalse(resolver.engineCanResolveURI(ctx),
            "FIX VERIFIED: ftp: uriToResolve must be rejected even with a file: baseUri");
    }

    /**
     * FIX: http: uriToResolve must also be rejected when baseUri is "file:".
     */
    @Test
    void testHttpUriIsRejectedWhenBaseUriIsFile() throws Exception {
        ResolverLocalFilesystem resolver = new ResolverLocalFilesystem();
        ResourceResolverContext ctx = makeContext("http://attacker.com/payload", "file:///var/app/");

        assertFalse(resolver.engineCanResolveURI(ctx),
            "FIX VERIFIED: http: uriToResolve must be rejected even with a file: baseUri");
    }

    /**
     * A relative uriToResolve (no scheme) combined with a file: baseUri is accepted —
     * this is the primary legitimate use case for providing a file: baseUri.
     */
    @Test
    void testRelativeUriWithFileBaseUriIsAccepted() throws Exception {
        ResolverLocalFilesystem resolver = new ResolverLocalFilesystem();
        ResourceResolverContext ctx = makeContext("subdoc.xml", "file:///var/app/");

        assertTrue(resolver.engineCanResolveURI(ctx),
            "A relative uriToResolve with a file: baseUri must be accepted");
    }

    /**
     * Sanity check: an https: URI with no baseUri (or a non-file: baseUri) is
     * correctly rejected by engineCanResolveURI.
     */
    @Test
    void testHttpsUriWithNullBaseUriIsRejected() throws Exception {
        ResolverLocalFilesystem resolver = new ResolverLocalFilesystem();
        ResourceResolverContext ctx = makeContext("https://attacker.com/payload", null);

        assertFalse(resolver.engineCanResolveURI(ctx),
            "https: URI with no baseUri should be rejected by the filesystem resolver");
    }

    /**
     * Sanity check: an https: URI with an https: baseUri is also correctly rejected.
     */
    @Test
    void testHttpsUriWithHttpsBaseUriIsRejected() throws Exception {
        ResolverLocalFilesystem resolver = new ResolverLocalFilesystem();
        ResourceResolverContext ctx = makeContext("https://attacker.com/payload", "https://victim.com/");

        assertFalse(resolver.engineCanResolveURI(ctx),
            "https: URI with https: baseUri should be rejected by the filesystem resolver");
    }

}
