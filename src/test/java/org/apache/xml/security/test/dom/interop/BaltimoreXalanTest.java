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

import org.apache.xml.security.test.dom.utils.resolver.OfflineResolver;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * This test is to ensure interoperability with the examples provided by Merlin Huges
 * from Baltimore using KeyTools XML. These test vectors are located in the directory
 * <CODE>ie/baltimore/merlin-examples/</CODE>. These tests require Xalan for the here() function
 *
 * @see <A HREF="http://www.baltimore.com/keytools/xml/index.html">The KeyTools XML Website</A>
 */
class BaltimoreXalanTest extends InteropTestBase {

    private static final String CONFIG_FILE = "/config-xalan.xml";

    private static final Logger LOG = System.getLogger(BaltimoreXalanTest.class.getName());

    private static final File merlinsDir16 = resolveFile("src", "test", "resources", "ie", "baltimore",
        "merlin-examples", "merlin-xmldsig-sixteen");
    private static final File merlinsDir23 = resolveFile("src", "test", "resources", "ie", "baltimore",
        "merlin-examples", "merlin-xmldsig-twenty-three");

    @BeforeAll
    public static void setup() {
        System.setProperty("org.apache.xml.security.allowUnsafeResourceResolving", "true");
        System.setProperty("org.apache.xml.security.resource.config", CONFIG_FILE);
        org.apache.xml.security.Init.init();
    }

    @AfterAll
    public static void cleanup() {
        System.clearProperty("org.apache.xml.security.allowUnsafeResourceResolving");
        System.clearProperty("org.apache.xml.security.resource.config");
    }

    /**
     * Method test_sixteen_external_dsa
     *
     * @throws Exception
     */
    @Test
    void test_sixteen_external_dsa() throws Exception {

        File file = new File(merlinsDir16, "signature.xml");
        ResourceResolverSpi resolver = new OfflineResolver();
        boolean followManifests = false;
        boolean verify = false;

        try {
            verify = this.verify(file, resolver, followManifests);
        } catch (RuntimeException ex) {
            LOG.log(Level.ERROR, "Verification crashed for " + file);
            throw ex;
        }

        if (!verify) {
            LOG.log(Level.ERROR, "Verification failed for " + file);
        }

        assertTrue(verify, file.toString());
    }

    /**
     * Method test_sixteen_bad_signature. This tests make sure that an
     * invalid signature is not valid. This is validating merlin's 16
     * signature but some of the referenced content has been modified so
     * some of the references should be invalid.
     *
     * @throws Exception
     */
    @Test
    void test_sixteen_bad_signature() throws Exception {

        File filename = new File(merlinsDir16, "bad-signature.xml");
        ResourceResolverSpi resolver = new OfflineResolver();
        boolean followManifests = false;
        boolean verify = false;

        try {
            verify = this.verify(filename, resolver, followManifests);
        } catch (RuntimeException ex) {
            LOG.log(Level.ERROR, "Verification crashed for " + filename);
            throw ex;
        }

        if (verify) {
            LOG.log(Level.ERROR, "Verification passed (should have failed) for " + filename);
        }

        assertFalse(verify, filename.toString());
    }


    /**
     * Method test_twenty_three_external_dsa_2
     *
     * @throws Exception
     */
    @Test
    void test_twenty_three_external_dsa_2() throws Exception {

        File filename = new File(merlinsDir23, "signature.xml");
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