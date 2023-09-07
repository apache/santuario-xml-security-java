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
import java.nio.file.Files;

import org.apache.xml.security.test.dom.utils.resolver.OfflineResolver;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * This test is to ensure interoperability with the examples provided by the IBM
 * XML Security Suite. They have to be located in the directory
 * <CODE>data/com/ibm/xss4j-20030127/</CODE>.
 * <p></p>
 * For license issues, the vectors are not included in the distibution. See
 * <A HREF="../../../../../../../interop.html">the interop page</A> for more on this.
 *
 * @see <A HREF="http://www.alphaworks.ibm.com/tech/xmlsecuritysuite">The IBM alphaWorks Website</A>
 */
/*
 * To make interop against the IBM xss4j examples, download the
 * XSS4j from http://www.alphaworks.ibm.com/tech/xmlsecuritysuite
 * and extract the test signatures from
 * xss4j-20030127.zip#/xss4j/data/dsig
 * in the directory
 * data/com/ibm/xss4j-20030127/
 * then the interop test is performed against these values, too.
 */
class IBMTest extends InteropTestBase {

    private static final Logger LOG = System.getLogger(IBMTest.class.getName());

    /** Field kentsDir           */
    private static final File kentsDir = resolveFile("data", "com", "ibm", "xss4j-20030127");

    static {
        org.apache.xml.security.Init.init();
    }

    private boolean runTests = false;

    /**
     * Constructor IBMTest
     */
    public IBMTest() {
        super();
        File f = resolveFile("src", "test", "resources", "com", "ibm", "xss4j-20011029", "enveloped-rsa.sig");
        if (f.exists()) {
            runTests = true;
        }
    }

    /**
     * Method test_enveloping_hmac
     *
     * @throws Exception
     */
    @Test
    void test_enveloping_hmac() throws Exception {
        if (!runTests) {
            return;
        }
        File filename = new File(kentsDir, "enveloping-hmac.sig");
        ResourceResolverSpi resolver = new OfflineResolver();
        boolean followManifests = false;
        byte[] hmacKey = Files.readAllBytes(new File(kentsDir, "enveloping-hmac.key").toPath());
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
     * Method test_detached_dsa
     *
     * @throws Exception
     */
    @Test
    void test_detached_dsa() throws Exception {
        if (!runTests) {
            return;
        }
        File filename = new File(kentsDir, "detached-dsa.sig");
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
     * Method test_detached_rsa
     *
     * @throws Exception
     */
    @Test
    void test_detached_rsa() throws Exception {
        if (!runTests) {
            return;
        }
        File filename = new File(kentsDir, "detached-rsa.sig");
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
     * Method test_enveloped_dsa
     *
     * @throws Exception
     */
    @Test
    void test_enveloped_dsa() throws Exception {
        if (!runTests) {
            return;
        }
        File filename = new File(kentsDir, "enveloped-dsa.sig");
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
     * Method test_enveloped_rsa
     *
     * @throws Exception
     */
    @Test
    void test_enveloped_rsa() throws Exception {
        if (!runTests) {
            return;
        }
        File filename = new File(kentsDir, "enveloped-rsa.sig");
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
     * Method test_enveloping_dsa
     *
     * @throws Exception
     */
    @Test
    void test_enveloping_dsa() throws Exception {
        if (!runTests) {
            return;
        }
        File filename = new File(kentsDir, "enveloping-dsa.sig");
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
     * Method test_enveloping_rsa
     *
     * @throws Exception
     */
    @Test
    void test_enveloping_rsa() throws Exception {
        if (!runTests) {
            return;
        }
        File filename = new File(kentsDir, "enveloping-rsa.sig");
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
     * Method test_enveloping_dsa_soaped_broken
     *
     * @throws Exception
     */
    @Test
    void test_enveloping_dsa_soaped_broken() throws Exception {
        if (!runTests) {
            return;
        }
        File filename = new File(kentsDir, "enveloping-dsa-soaped-broken.sig");
        if (!filename.exists() ) {
            System.err.println("Couldn't find: " + filename + " and couldn't do the test");
            return;
        }
        ResourceResolverSpi resolver = null;
        boolean followManifests = false;
        boolean verify = true;

        try {
            verify = this.verify(filename, resolver, followManifests);
        } catch (RuntimeException ex) {
            LOG.log(Level.ERROR, "Verification crashed for " + filename);
            throw ex;
        }

        if (verify) {
            LOG.log(Level.ERROR, "Verification failed for " + filename + ", had to be broken but was successful");
        }

        assertFalse(verify, filename.toString());
    }

    /**
     * Method test_enveloping_exclusive
     *
     * @throws Exception
     * $todo$ implement exclusive-c14n
     */
    @Disabled
    public void _not_active_test_enveloping_exclusive() throws Exception {
        // exclusive c14n not supported yet
    }

    /**
     * Method test_enveloping_exclusive_soaped
     *
     * @throws Exception
     * $todo$ implement exclusive-c14n
     */
    @Disabled
    public void _not_active_test_enveloping_exclusive_soaped() throws Exception {
        // exclusive c14n not supported yet
    }

}
