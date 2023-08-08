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

import org.apache.xml.security.signature.MissingResourceFailureException;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.test.dom.utils.resolver.OfflineResolver;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.junit.jupiter.api.Test;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * This test is to ensure interoperability with the examples provided by Merlin Huges
 * from Baltimore using KeyTools XML. These test vectors are located in the directory
 * <CODE>data/ie/baltimore/merlin-examples/</CODE>.
 *
 * @see <A HREF="http://www.baltimore.com/keytools/xml/index.html">The KeyTools XML Website</A>
 */
class BaltimoreTest extends InteropTestBase {

    private static final Logger LOG = System.getLogger(BaltimoreTest.class.getName());

    /** Field merlinsDir15           */
    private static final File merlinsDir15;
    private static final File merlinsDir16;
    private static final File merlinsDir23;

    static {
        System.setProperty("org.apache.xml.security.allowUnsafeResourceResolving", "true");
        merlinsDir15 = resolveFile("src", "test", "resources", "ie", "baltimore", "merlin-examples", "merlin-xmldsig-fifteen");
        merlinsDir16 = resolveFile("src", "test", "resources", "ie", "baltimore", "merlin-examples", "merlin-xmldsig-sixteen");
        merlinsDir23 = resolveFile("src", "test", "resources", "ie", "baltimore", "merlin-examples", "merlin-xmldsig-twenty-three");
        org.apache.xml.security.Init.init();
    }

    /**
     * Constructor BaltimoreTest
     */
    public BaltimoreTest() {
        super();
    }

    /**
     * Method test_fifteen_enveloping_hmac_sha1
     *
     * @throws Exception
     */
    @Test
    void test_fifteen_enveloping_hmac_sha1() throws Exception {

        File filename = new File(merlinsDir15, "signature-enveloping-hmac-sha1.xml");
        boolean verify = this.verifyHMAC(filename, new OfflineResolver(), false,
                                         "secret".getBytes(StandardCharsets.US_ASCII));

        if (!verify) {
            LOG.log(Level.ERROR, "Verification failed for " + filename);
        }

        assertTrue(verify, filename.toString());
    }

    /**
     * Method test_fifteen_enveloping_hmac_sha1_40
     *
     * @throws Exception
     */
    @Test
    void test_fifteen_enveloping_hmac_sha1_40() throws Exception {

        File filename = new File(merlinsDir15, "signature-enveloping-hmac-sha1-40.xml");
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
     * Method test_fifteen_enveloped_dsa
     *
     * @throws Exception
     */
    @Test
    void test_fifteen_enveloped_dsa() throws Exception {

        File filename = new File(merlinsDir15, "signature-enveloped-dsa.xml");
        ResourceResolverSpi resolver = new OfflineResolver();
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
     * Method test_fifteen_enveloping_b64_dsa
     *
     * @throws Exception
     */
    @Test
    void test_fifteen_enveloping_b64_dsa() throws Exception {

        File filename = new File(merlinsDir15, "signature-enveloping-b64-dsa.xml");
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
     * Method test_fifteen_enveloping_dsa
     *
     * @throws Exception
     */
    @Test
    void test_fifteen_enveloping_dsa() throws Exception {

        File filename = new File(merlinsDir15, "signature-enveloping-dsa.xml");
        ResourceResolverSpi resolver = new OfflineResolver();
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
     * Method test_fifteen_enveloping_rsa
     *
     * @throws Exception
     */
    @Test
    void test_fifteen_enveloping_rsa() throws Exception {

        File filename = new File(merlinsDir15, "signature-enveloping-rsa.xml");
        ResourceResolverSpi resolver = new OfflineResolver();
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
     * Method test_fifteen_external_b64_dsa
     *
     * @throws Exception
     */
    @Test
    void test_fifteen_external_b64_dsa() throws Exception {

        File filename = new File(merlinsDir15, "signature-external-b64-dsa.xml");
        ResourceResolverSpi resolver = new OfflineResolver();
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
     * Method test_fifteen_external_dsa
     *
     * @throws Exception
     */
    @Test
    void test_fifteen_external_dsa() throws Exception {

        File filename = new File(merlinsDir15, "signature-external-dsa.xml");
        ResourceResolverSpi resolver = new OfflineResolver();
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
     * Method test_sixteen_bad_signature. This should fail due to lack of support for the here() function
     * as we don't have Xalan installed.
     */
    @Test
    void test_sixteen_bad_signature() throws Exception {

        File filename = new File(merlinsDir16, "bad-signature.xml");
        ResourceResolverSpi resolver = new OfflineResolver();
        boolean followManifests = false;

        try {
            this.verify(filename, resolver, followManifests);
            fail("Failure expected due to no support for the here() function");
        } catch (MissingResourceFailureException ex) {
            assertTrue(ex.getCause().getMessage().contains("Could not find function: here"));
        }
    }

    /**
     * Method test_twenty_three_enveloping_hmac_sha1
     *
     * @throws Exception
     */
    @Test
    void test_twenty_three_enveloping_hmac_sha1() throws Exception {

        File filename = new File(merlinsDir23, "signature-enveloping-hmac-sha1.xml");
        boolean verify = this.verifyHMAC(filename, new OfflineResolver(), false,
                                         "secret".getBytes(StandardCharsets.US_ASCII));

        if (!verify) {
            LOG.log(Level.ERROR, "Verification failed for " + filename);
        }

        assertTrue(verify, filename.toString());
    }

    /**
     * Method test_twenty_three_enveloping_hmac_sha1_40
     *
     * @throws Exception
     */
    @Test
    void test_twenty_three_enveloping_hmac_sha1_40() throws Exception {

        File filename = new File(merlinsDir23, "signature-enveloping-hmac-sha1-40.xml");
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
     * Method test_twenty_three_enveloped_dsa
     *
     * @throws Exception
     */
    @Test
    void test_twenty_three_enveloped_dsa() throws Exception {

        File filename = new File(merlinsDir23, "signature-enveloped-dsa.xml");
        ResourceResolverSpi resolver = new OfflineResolver();
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
     * Method test_twenty_three_enveloping_b64_dsa
     *
     * @throws Exception
     */
    @Test
    void test_twenty_three_enveloping_b64_dsa() throws Exception {

        File filename = new File(merlinsDir23, "signature-enveloping-b64-dsa.xml");
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
     * Method test_twenty_three_enveloping_dsa
     *
     * @throws Exception
     */
    @Test
    void test_twenty_three_enveloping_dsa() throws Exception {

        File filename = new File(merlinsDir23, "signature-enveloping-dsa.xml");
        ResourceResolverSpi resolver = new OfflineResolver();
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
     * Method test_twenty_three_enveloping_rsa
     *
     * @throws Exception
     */
    @Test
    void test_twenty_three_enveloping_rsa() throws Exception {

        File filename = new File(merlinsDir23, "signature-enveloping-rsa.xml");
        ResourceResolverSpi resolver = new OfflineResolver();
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
     * Method test_twenty_three_external_b64_dsa
     *
     * @throws Exception
     */
    @Test
    void test_twenty_three_external_b64_dsa() throws Exception {

        File filename = new File(merlinsDir23, "signature-external-b64-dsa.xml");
        ResourceResolverSpi resolver = new OfflineResolver();
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
     * Method test_twenty_three_external_dsa
     *
     * @throws Exception
     */
    @Test
    void test_twenty_three_external_dsa() throws Exception {

        File filename = new File(merlinsDir23, "signature-external-dsa.xml");
        ResourceResolverSpi resolver = new OfflineResolver();
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