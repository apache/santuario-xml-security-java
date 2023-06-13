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

import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;

import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * This test is to ensure interoperability with the examples provided by Blake Dournaee
 * from RSA Security using Cert-J 2.01. These test vectors are located in the directory
 * <CODE>data/com/rsasecurity/bdournaee/</CODE>.
 *
 * @see <A HREF="http://www.rsasecurity.com/products/bsafe/certj.html">RSA BSAFE Cert-J</A>
 */
public class RSASecurityTest extends InteropTestBase {

    static org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(RSASecurityTest.class);

    /** Field blakesDir           */
    static File blakesDir;

    static {
        blakesDir = XmlSecTestEnvironment.resolveFile("src", "test", "resources", "com", "rsasecurity", "bdournaee");
        org.apache.xml.security.Init.init();
    }

    @org.junit.jupiter.api.Test
    public void test_enveloping() throws Exception {

        File filename = new File(blakesDir, "certj201_enveloping.xml");
        boolean followManifests = false;
        ResourceResolverSpi resolver = null;
        boolean verify = this.verify(filename, resolver, followManifests);

        if (!verify) {
            LOG.error("Verification failed for " + filename);
        }

        assertTrue(verify, filename.toString());
    }

    @org.junit.jupiter.api.Test
    public void test_enveloped() throws Exception {

        File filename = new File(blakesDir, "certj201_enveloped.xml");
        boolean followManifests = false;
        ResourceResolverSpi resolver = null;
        boolean verify = this.verify(filename, resolver, followManifests);

        if (!verify) {
            LOG.error("Verification failed for " + filename);
        }

        assertTrue(verify, filename.toString());
    }

}