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
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
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
class IAIKTest extends InteropTestBase {

    private static final Logger LOG = System.getLogger(IAIKTest.class.getName());

    /** Field gregorsDir */
    private static final Path gregorsDir;

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
    void test_signatureAlgorithms_signatures_hMACShortSignature()
        throws Exception {

        File filename = resolveFile(gregorsDir, "signatureAlgorithms", "signatures", "hMACShortSignature.xml");
        ResourceResolverSpi resolver = new OfflineResolver();
        boolean followManifests = false;
        byte[] hmacKey = "secret".getBytes(StandardCharsets.US_ASCII);

        try {
            this.verifyHMAC(filename, resolver, followManifests, hmacKey);
            fail("HMACOutputLength Exception not caught");
        } catch (RuntimeException ex) {
            LOG.log(Level.ERROR, "Verification crashed for " + filename);
            throw ex;
        } catch (XMLSignatureException ex) {
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
    void test_signatureAlgorithms_signatures_hMACSignature()
        throws Exception {

        File filename = resolveFile(gregorsDir, "signatureAlgorithms", "signatures", "hMACSignature.xml");
        ResourceResolverSpi resolver = new OfflineResolver();
        boolean followManifests = false;
        byte[] hmacKey = "secret".getBytes(StandardCharsets.US_ASCII);
        boolean verify = false;

        try {
            verify = this.verifyHMAC(filename, resolver, followManifests, hmacKey);
        } catch (RuntimeException ex) {
            LOG.log(Level.ERROR, "Verification crashed for " + filename);

            throw ex;
        }

        if (!verify) {
            LOG.log(Level.ERROR, "Verification failed for " + filename);
        }

        assertTrue(verify, filename.toString());
    }

    /**
     * Method test_coreFeatures_signatures_manifestSignature
     *
     * @throws Exception
     */
    @Test
    void test_coreFeatures_signatures_manifestSignature_core()
        throws Exception {

        File filename = resolveFile(gregorsDir, "coreFeatures", "signatures", "manifestSignature.xml");
        ResourceResolverSpi resolver = null;
        boolean followManifests = false;
        boolean verify = false;

        try {
            verify = this.verify(filename, resolver, followManifests);
        } catch (RuntimeException ex) {
            LOG.log(Level.ERROR, "Core validation crashed for " + filename);

            throw ex;
        }

        if (!verify) {
            LOG.log(Level.ERROR, "Core validation failed for " + filename);
        }

        assertTrue(verify, "Core validation failed for " + filename);
    }

    /**
     * Method test_coreFeatures_signatures_manifestSignature_manifest
     *
     * @throws Exception
     */
    @Test
    void test_coreFeatures_signatures_manifestSignature_manifest()
        throws Exception {

        File filename = resolveFile(gregorsDir, "coreFeatures", "signatures", "manifestSignature.xml");
        ResourceResolverSpi resolver = null;
        boolean followManifests = true;
        boolean verify = false;

        try {
            verify = this.verify(filename, resolver, followManifests, false);
        } catch (RuntimeException ex) {
            LOG.log(Level.ERROR, "Verification crashed for " + filename);

            throw ex;
        }

        if (!verify) {
            LOG.log(Level.ERROR, "Following the ds:Manifest failed for " + filename);
        }

        assertTrue(verify, "Following the ds:Manifest failed for " + filename);
    }

    /**
     * Method test_coreFeatures_signatures_signatureTypesSignature
     *
     * @throws Exception
     */
    @Test
    void test_coreFeatures_signatures_signatureTypesSignature()
        throws Exception {

        File filename = resolveFile(gregorsDir, "coreFeatures", "signatures", "signatureTypesSignature.xml");
        ResourceResolverSpi resolver = new OfflineResolver();
        boolean followManifests = false;
        boolean verify = false;

        try {
            verify = this.verify(filename, resolver, followManifests, false     );
        } catch (RuntimeException ex) {
            LOG.log(Level.ERROR, "Verification crashed for " + filename);

            throw ex;
        }

        if (!verify) {
            LOG.log(Level.ERROR, "Verification failed for " + filename);
        }

        assertTrue(verify, "Verification failed for " + filename);
    }

    /**
     * Method test_coreFeatures_signatures_anonymousReferenceSignature
     *
     * @throws Exception
     */
    @Test
    void test_coreFeatures_signatures_anonymousReferenceSignature()
        throws Exception {

        File filename = resolveFile(gregorsDir, "coreFeatures", "signatures", "anonymousReferenceSignature.xml");
        String anonymousRef = resolveFile(gregorsDir, "coreFeatures", "samples", "anonymousReferenceContent.xml")
            .getAbsolutePath();
        ResourceResolverSpi resolver = new ResolverAnonymous(anonymousRef);
        boolean followManifests = false;
        boolean verify = false;

        try {
            verify = this.verify(filename, resolver, followManifests);
        } catch (RuntimeException ex) {
            LOG.log(Level.ERROR, "Verification crashed for " + filename);

            throw ex;
        }

        if (!verify) {
            LOG.log(Level.ERROR, "Verification failed for " + filename);
        }

        assertTrue(verify, filename.toString());
    }

    /**
     * Method test_signatureAlgorithms_signatures_dSASignature
     *
     * @throws Exception
     */
    @Test
    void test_signatureAlgorithms_signatures_dSASignature()
        throws Exception {

        File filename = resolveFile(gregorsDir, "signatureAlgorithms", "signatures", "dSASignature.xml");
        ResourceResolverSpi resolver = null;
        boolean followManifests = false;
        boolean verify = false;

        try {
            verify = this.verify(filename, resolver, followManifests);
        } catch (RuntimeException ex) {
            LOG.log(Level.ERROR, "Verification crashed for " + filename);

            throw ex;
        }

        if (!verify) {
            LOG.log(Level.ERROR, "Verification failed for " + filename);
        }

        assertTrue(verify, filename.toString());
    }

    /**
     * Method test_signatureAlgorithms_signatures_rSASignature
     *
     * @throws Exception
     */
    @Test
    void test_signatureAlgorithms_signatures_rSASignature()
        throws Exception {

        File filename = resolveFile(gregorsDir, "signatureAlgorithms", "signatures", "rSASignature.xml");
        ResourceResolverSpi resolver = null;
        boolean followManifests = false;
        boolean verify = false;

        try {
            verify = this.verify(filename, resolver, followManifests);
        } catch (RuntimeException ex) {
            LOG.log(Level.ERROR, "Verification crashed for " + filename);

            throw ex;
        }

        if (!verify) {
            LOG.log(Level.ERROR, "Verification failed for " + filename);
        }

        assertTrue(verify, filename.toString());
    }

    /**
     * Method test_transforms_signatures_base64DecodeSignature
     *
     * @throws Exception
     */
    @Test
    void test_transforms_signatures_base64DecodeSignature()
        throws Exception {

        File filename = resolveFile(gregorsDir, "transforms", "signatures", "base64DecodeSignature.xml");
        ResourceResolverSpi resolver = null;
        boolean followManifests = false;
        boolean verify = false;

        try {
            verify = this.verify(filename, resolver, followManifests, false);
        } catch (RuntimeException ex) {
            LOG.log(Level.ERROR, "Verification crashed for " + filename);

            throw ex;
        }

        if (!verify) {
            LOG.log(Level.ERROR, "Verification failed for " + filename);
        }

        assertTrue(verify, filename.toString());
    }

    /**
     * Method test_transforms_signatures_c14nSignature
     *
     * @throws Exception
     */
    @Test
    void test_transforms_signatures_c14nSignature() throws Exception {

        File filename = resolveFile(gregorsDir, "transforms", "signatures", "c14nSignature.xml");
        ResourceResolverSpi resolver = null;
        boolean followManifests = false;
        boolean verify = false;

        try {
            verify = this.verify(filename, resolver, followManifests, false);
        } catch (RuntimeException ex) {
            LOG.log(Level.ERROR, "Verification crashed for " + filename);

            throw ex;
        }

        if (!verify) {
            LOG.log(Level.ERROR, "Verification failed for " + filename);
        }

        assertTrue(verify, filename.toString());
    }

    /**
     * Method test_transforms_signatures_envelopedSignatureSignature
     *
     * @throws Exception
     */
    @Test
    void test_transforms_signatures_envelopedSignatureSignature()
        throws Exception {

        File filename = resolveFile(gregorsDir, "transforms", "signatures", "envelopedSignatureSignature.xml");
        ResourceResolverSpi resolver = null;
        boolean followManifests = false;
        boolean verify = false;

        try {
            verify = this.verify(filename, resolver, followManifests);
        } catch (RuntimeException ex) {
            LOG.log(Level.ERROR, "Verification crashed for " + filename);

            throw ex;
        }

        if (!verify) {
            LOG.log(Level.ERROR, "Verification failed for " + filename);
        }

        assertTrue(verify, filename.toString());
    }

    /**
     * Method test_transforms_signatures_xPathSignature
     *
     * @throws Exception
     */
    @Test
    void test_transforms_signatures_xPathSignature() throws Exception {

        File filename = resolveFile(gregorsDir, "transforms", "signatures", "xPathSignature.xml");
        ResourceResolverSpi resolver = null;
        boolean followManifests = false;
        boolean verify = false;

        try {
            verify = this.verify(filename, resolver, followManifests);
        } catch (RuntimeException ex) {
            LOG.log(Level.ERROR, "Verification crashed for " + filename);

            throw ex;
        }

        if (!verify) {
            LOG.log(Level.ERROR, "Verification failed for " + filename);
        }

        assertTrue(verify, filename.toString());
    }

}