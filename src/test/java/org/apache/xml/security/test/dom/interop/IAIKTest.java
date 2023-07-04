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
package org.apache.xml.security.test.dom.interop;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.test.dom.utils.resolver.OfflineResolver;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.apache.xml.security.utils.resolver.implementations.ResolverAnonymous;
import org.apache.xml.security.utils.resolver.implementations.ResolverLocalFilesystem;
import org.junit.jupiter.api.Test;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.apache.xml.security.test.XmlSecTestEnvironment.resolvePath;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * This test is to ensure interoperability with the examples provided by the IAIK
 * XML Signature implementation. Thanks to Gregor Karlinger who provided these
 * test vectors. They are located in the directory <CODE>data/at/iaik/ixsil/</CODE>.
 *
 * @see <A HREF="http://jcewww.iaik.at/products/ixsil/index.php">The IAIK IXSIL Website</A>
 */
public class IAIKTest extends InteropTestBase {

    static org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(IAIKTest.class);

    /** Field gregorsDir */
    static Path gregorsDir;

    static {
        gregorsDir = resolvePath("src", "test", "resources", "at", "iaik", "ixsil");
        org.apache.xml.security.Init.init();
        ResourceResolver.register(new ResolverLocalFilesystem(), false);
    }

    /**
     * Method test_signatureAlgorithms_signatures_hMACShortSignature
     *
     * @throws Exception
     */
    @Test
    public void test_signatureAlgorithms_signatures_hMACShortSignature()
        throws Exception {

        final File filename = resolveFile(gregorsDir, "signatureAlgorithms", "signatures", "hMACShortSignature.xml");
        final ResourceResolverSpi resolver = new OfflineResolver();
        final boolean followManifests = false;
        final byte[] hmacKey = "secret".getBytes(StandardCharsets.US_ASCII);

        try {
            this.verifyHMAC(filename, resolver, followManifests, hmacKey);
            fail("HMACOutputLength Exception not caught");
        } catch (final RuntimeException ex) {
            LOG.error("Verification crashed for " + filename);
            throw ex;
        } catch (final XMLSignatureException ex) {
            if (!"algorithms.HMACOutputLengthMin".equals(ex.getMsgID())) {
                fail(ex.getMessage());
            }
        }
    }

    /**
     * Method test_signatureAlgorithms_signatures_hMACSignature
     *
     * @throws Exception
     */
    @Test
    public void test_signatureAlgorithms_signatures_hMACSignature()
        throws Exception {

        final File filename = resolveFile(gregorsDir, "signatureAlgorithms", "signatures", "hMACSignature.xml");
        final ResourceResolverSpi resolver = new OfflineResolver();
        final boolean followManifests = false;
        final byte[] hmacKey = "secret".getBytes(StandardCharsets.US_ASCII);
        boolean verify = false;

        try {
            verify = this.verifyHMAC(filename, resolver, followManifests, hmacKey);
        } catch (final RuntimeException ex) {
            LOG.error("Verification crashed for " + filename);

            throw ex;
        }

        if (!verify) {
            LOG.error("Verification failed for " + filename);
        }

        assertTrue(verify, filename.toString());
    }

    /**
     * Method test_coreFeatures_signatures_manifestSignature
     *
     * @throws Exception
     */
    @Test
    public void test_coreFeatures_signatures_manifestSignature_core()
        throws Exception {

        final File filename = resolveFile(gregorsDir, "coreFeatures", "signatures", "manifestSignature.xml");
        final ResourceResolverSpi resolver = null;
        final boolean followManifests = false;
        boolean verify = false;

        try {
            verify = this.verify(filename, resolver, followManifests);
        } catch (final RuntimeException ex) {
            LOG.error("Core validation crashed for " + filename);

            throw ex;
        }

        if (!verify) {
            LOG.error("Core validation failed for " + filename);
        }

        assertTrue(verify, "Core validation failed for " + filename);
    }

    /**
     * Method test_coreFeatures_signatures_manifestSignature_manifest
     *
     * @throws Exception
     */
    @Test
    public void test_coreFeatures_signatures_manifestSignature_manifest()
        throws Exception {

        final File filename = resolveFile(gregorsDir, "coreFeatures", "signatures", "manifestSignature.xml");
        final ResourceResolverSpi resolver = null;
        final boolean followManifests = true;
        boolean verify = false;

        try {
            verify = this.verify(filename, resolver, followManifests, false);
        } catch (final RuntimeException ex) {
            LOG.error("Verification crashed for " + filename);

            throw ex;
        }

        if (!verify) {
            LOG.error("Following the ds:Manifest failed for " + filename);
        }

        assertTrue(verify, "Following the ds:Manifest failed for " + filename);
    }

    /**
     * Method test_coreFeatures_signatures_signatureTypesSignature
     *
     * @throws Exception
     */
    @Test
    public void test_coreFeatures_signatures_signatureTypesSignature()
        throws Exception {

        final File filename = resolveFile(gregorsDir, "coreFeatures", "signatures", "signatureTypesSignature.xml");
        final ResourceResolverSpi resolver = new OfflineResolver();
        final boolean followManifests = false;
        boolean verify = false;

        try {
            verify = this.verify(filename, resolver, followManifests, false     );
        } catch (final RuntimeException ex) {
            LOG.error("Verification crashed for " + filename);

            throw ex;
        }

        if (!verify) {
            LOG.error("Verification failed for " + filename);
        }

        assertTrue(verify, "Verification failed for " + filename);
    }

    /**
     * Method test_coreFeatures_signatures_anonymousReferenceSignature
     *
     * @throws Exception
     */
    @Test
    public void test_coreFeatures_signatures_anonymousReferenceSignature()
        throws Exception {

        final File filename = resolveFile(gregorsDir, "coreFeatures", "signatures", "anonymousReferenceSignature.xml");
        final String anonymousRef = resolveFile(gregorsDir, "coreFeatures", "samples", "anonymousReferenceContent.xml")
            .getAbsolutePath();
        final ResourceResolverSpi resolver = new ResolverAnonymous(anonymousRef);
        final boolean followManifests = false;
        boolean verify = false;

        try {
            verify = this.verify(filename, resolver, followManifests);
        } catch (final RuntimeException ex) {
            LOG.error("Verification crashed for " + filename);

            throw ex;
        }

        if (!verify) {
            LOG.error("Verification failed for " + filename);
        }

        assertTrue(verify, filename.toString());
    }

    /**
     * Method test_signatureAlgorithms_signatures_dSASignature
     *
     * @throws Exception
     */
    @Test
    public void test_signatureAlgorithms_signatures_dSASignature()
        throws Exception {

        final File filename = resolveFile(gregorsDir, "signatureAlgorithms", "signatures", "dSASignature.xml");
        final ResourceResolverSpi resolver = null;
        final boolean followManifests = false;
        boolean verify = false;

        try {
            verify = this.verify(filename, resolver, followManifests);
        } catch (final RuntimeException ex) {
            LOG.error("Verification crashed for " + filename);

            throw ex;
        }

        if (!verify) {
            LOG.error("Verification failed for " + filename);
        }

        assertTrue(verify, filename.toString());
    }

    /**
     * Method test_signatureAlgorithms_signatures_rSASignature
     *
     * @throws Exception
     */
    @Test
    public void test_signatureAlgorithms_signatures_rSASignature()
        throws Exception {

        final File filename = resolveFile(gregorsDir, "signatureAlgorithms", "signatures", "rSASignature.xml");
        final ResourceResolverSpi resolver = null;
        final boolean followManifests = false;
        boolean verify = false;

        try {
            verify = this.verify(filename, resolver, followManifests);
        } catch (final RuntimeException ex) {
            LOG.error("Verification crashed for " + filename);

            throw ex;
        }

        if (!verify) {
            LOG.error("Verification failed for " + filename);
        }

        assertTrue(verify, filename.toString());
    }

    /**
     * Method test_transforms_signatures_base64DecodeSignature
     *
     * @throws Exception
     */
    @Test
    public void test_transforms_signatures_base64DecodeSignature()
        throws Exception {

        final File filename = resolveFile(gregorsDir, "transforms", "signatures", "base64DecodeSignature.xml");
        final ResourceResolverSpi resolver = null;
        final boolean followManifests = false;
        boolean verify = false;

        try {
            verify = this.verify(filename, resolver, followManifests, false);
        } catch (final RuntimeException ex) {
            LOG.error("Verification crashed for " + filename);

            throw ex;
        }

        if (!verify) {
            LOG.error("Verification failed for " + filename);
        }

        assertTrue(verify, filename.toString());
    }

    /**
     * Method test_transforms_signatures_c14nSignature
     *
     * @throws Exception
     */
    @Test
    public void test_transforms_signatures_c14nSignature() throws Exception {

        final File filename = resolveFile(gregorsDir, "transforms", "signatures", "c14nSignature.xml");
        final ResourceResolverSpi resolver = null;
        final boolean followManifests = false;
        boolean verify = false;

        try {
            verify = this.verify(filename, resolver, followManifests, false);
        } catch (final RuntimeException ex) {
            LOG.error("Verification crashed for " + filename);

            throw ex;
        }

        if (!verify) {
            LOG.error("Verification failed for " + filename);
        }

        assertTrue(verify, filename.toString());
    }

    /**
     * Method test_transforms_signatures_envelopedSignatureSignature
     *
     * @throws Exception
     */
    @Test
    public void test_transforms_signatures_envelopedSignatureSignature()
        throws Exception {

        final File filename = resolveFile(gregorsDir, "transforms", "signatures", "envelopedSignatureSignature.xml");
        final ResourceResolverSpi resolver = null;
        final boolean followManifests = false;
        boolean verify = false;

        try {
            verify = this.verify(filename, resolver, followManifests);
        } catch (final RuntimeException ex) {
            LOG.error("Verification crashed for " + filename);

            throw ex;
        }

        if (!verify) {
            LOG.error("Verification failed for " + filename);
        }

        assertTrue(verify, filename.toString());
    }

    /**
     * Method test_transforms_signatures_xPathSignature
     *
     * @throws Exception
     */
    @Test
    public void test_transforms_signatures_xPathSignature() throws Exception {

        final File filename = resolveFile(gregorsDir, "transforms", "signatures", "xPathSignature.xml");
        final ResourceResolverSpi resolver = null;
        final boolean followManifests = false;
        boolean verify = false;

        try {
            verify = this.verify(filename, resolver, followManifests);
        } catch (final RuntimeException ex) {
            LOG.error("Verification crashed for " + filename);

            throw ex;
        }

        if (!verify) {
            LOG.error("Verification failed for " + filename);
        }

        assertTrue(verify, filename.toString());
    }

}