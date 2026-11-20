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

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.Init;
import org.apache.xml.security.stax.config.ResourceResolverMapper;
import org.apache.xml.security.stax.impl.resourceResolvers.ResolverFilesystem;
import org.apache.xml.security.stax.impl.resourceResolvers.ResolverHttp;
import org.apache.xml.security.stax.impl.resourceResolvers.ResolverXPointer;
import org.apache.xml.security.utils.JavaUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests that the StAX http and filesystem resolvers only accept URIs with
 * their own scheme, and only fall back to the base URI for relative references.
 */
class ResolverSchemeTest {

    private final ResolverHttp http = new ResolverHttp();
    private final ResolverFilesystem fs = new ResolverFilesystem();

    @Test
    void testHttpResolverAcceptsHttpAndHttps() {
        assertNotNull(http.canResolve("http://example.com/a.xml", null));
        assertNotNull(http.canResolve("https://example.com/a.xml", null));
        assertNotNull(http.canResolve("a.xml", "http://example.com/"));
        assertNotNull(http.canResolve("a.xml", "https://example.com/"));
        assertNotNull(http.canResolve("/a.xml", "https://example.com/dir/"));
    }

    @Test
    void testHttpResolverRejectsOtherSchemesWithHttpBaseURI() {
        assertNull(http.canResolve("file:///etc/passwd", "http://example.com/"));
        assertNull(http.canResolve("ftp://example.com/a.xml", "https://example.com/"));
        assertNull(http.canResolve("jar:file:///app.jar!/a.xml", "http://example.com/"));
    }

    @Test
    void testHttpResolverRejectsRelativeURIWithoutHttpBaseURI() {
        assertNull(http.canResolve(null, "http://example.com/"));
        assertNull(http.canResolve("a.xml", null));
        assertNull(http.canResolve("a.xml", "file:///tmp/"));
    }

    @Test
    void testHttpResolverRejectsSameDocumentReferences() {
        assertNull(http.canResolve("", "http://example.com/"));
        assertNull(http.canResolve("#id", "https://example.com/"));
        assertNull(http.canResolve("#xpointer(/)", "http://example.com/"));
        assertNull(http.canResolve("#xpointer(id('id'))", "https://example.com/"));
    }

    @Test
    void testFilesystemResolverAcceptsFile() {
        assertNotNull(fs.canResolve("file:///tmp/a.xml", null));
        assertNotNull(fs.canResolve("file:///tmp/a.xml", "http://example.com/"));
        assertNotNull(fs.canResolve("a.xml", "file:///tmp/"));
    }

    @Test
    void testFilesystemResolverRejectsOtherSchemesWithFileBaseURI() {
        assertNull(fs.canResolve("http://169.254.169.254/latest/meta-data/", "file:///tmp/"));
        assertNull(fs.canResolve("https://example.com/a.xml", "file:///tmp/"));
        assertNull(fs.canResolve("ftp://example.com/a.xml", "file:///tmp/"));
        assertNull(fs.canResolve("jar:http://example.com/a.jar!/a.xml", "file:///tmp/"));
    }

    @Test
    void testFilesystemResolverRejectsRelativeURIWithoutFileBaseURI() {
        assertNull(fs.canResolve(null, "file:///tmp/"));
        assertNull(fs.canResolve("a.xml", null));
        assertNull(fs.canResolve("a.xml", "http://example.com/"));
    }

    @Test
    void testFilesystemResolverRejectsSameDocumentReferences() {
        assertNull(fs.canResolve("", "file:///tmp/"));
        assertNull(fs.canResolve("#id", "file:///tmp/"));
        assertNull(fs.canResolve("#xpointer(/)", "file:///tmp/"));
        assertNull(fs.canResolve("#xpointer(id('id'))", "file:///tmp/"));
    }

    @Test
    void testXPointerReferenceWithBaseURIUsesXPointerResolver() throws Exception {
        Init.init(this.getClass().getClassLoader().getResource("security-config.xml").toURI(), this.getClass());
        assertInstanceOf(ResolverXPointer.class,
            ResourceResolverMapper.getResourceResolver("#xpointer(/)", "file:///tmp/"));
        assertInstanceOf(ResolverXPointer.class,
            ResourceResolverMapper.getResourceResolver("#xpointer(id('id'))", "http://example.com/"));
    }

    @Test
    void testFilesystemResolverReadsRelativeFile(@TempDir Path dir) throws Exception {
        Files.write(dir.resolve("a.xml"), "<a/>".getBytes(StandardCharsets.UTF_8));
        String baseURI = dir.toUri().toString();
        assertNotNull(fs.canResolve("a.xml", baseURI));
        try (InputStream is = fs.newInstance("a.xml", baseURI).getInputStreamFromExternalReference()) {
            assertEquals("<a/>", new String(JavaUtils.getBytesFromStream(is), StandardCharsets.UTF_8));
        }
    }

    /**
     * A scheme-relative reference is accepted under a file: base, but the resulting
     * file://host/... URI must not be opened over the network (URL.openStream() falls
     * back to FTP for a file: URL with a remote host).
     */
    @Test
    @DisabledOnOs(OS.WINDOWS) // Path.of maps file://host/... to a UNC path on Windows
    void testFilesystemResolverDoesNotOpenRemoteHost() {
        XMLSecurityException ex = assertThrows(XMLSecurityException.class,
            () -> fs.newInstance("//127.0.0.1:9/a.xml", "file:///tmp/").getInputStreamFromExternalReference());
        assertInstanceOf(IllegalArgumentException.class, ex.getCause());
    }

    /**
     * Even if a non-file URI reaches the filesystem resolver, it must only ever
     * open local files, never make a network connection.
     */
    @Test
    void testFilesystemResolverDoesNotOpenNonFileURI() {
        XMLSecurityException ex = assertThrows(XMLSecurityException.class,
            () -> fs.newInstance("http://127.0.0.1:9/a.xml", null).getInputStreamFromExternalReference());
        assertTrue(ex.getCause() instanceof FileSystemNotFoundException
            || ex.getCause() instanceof IllegalArgumentException, String.valueOf(ex.getCause()));
    }
}
