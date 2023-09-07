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
package org.apache.xml.security.test.dom.keys.content.x509;


import java.io.File;
import java.io.FileInputStream;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;

import org.apache.xml.security.keys.content.x509.XMLX509SKI;
import org.apache.xml.security.test.dom.TestUtils;
import org.junit.jupiter.api.Test;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Test bugfix 41892: XML Security 1.4.0 does not build with IBM's JDK
 */
class XMLX509SKITest {

    private final CertificateFactory cf;

    public XMLX509SKITest() throws Exception {
        cf = CertificateFactory.getInstance("X.509");
    }

    @Test
    void testGetSKIBytesFromCert() throws Exception {
        File f = resolveFile("src/test/resources/ie/baltimore/merlin-examples/merlin-xmldsig-twenty-three/certs/lugh.crt");
        X509Certificate cert;
        try (FileInputStream fis = new FileInputStream(f)) {
            cert = (X509Certificate) cf.generateCertificate(fis);
        }

        // Get subject key identifier from certificate
        byte[] skid = XMLX509SKI.getSKIBytesFromCert(cert);

        // Use X509CertSelector to match on certificate using the skid,
        // thereby testing that the returned skid was correct
        X509CertSelector xcs = new X509CertSelector();
        // DER-encode skid - required by X509CertSelector
        byte[] encodedSkid = new byte[skid.length+2];
        encodedSkid[0] = 0x04; // OCTET STRING tag value
        encodedSkid[1] = (byte) skid.length; // length
        System.arraycopy(skid, 0, encodedSkid, 2, skid.length);
        xcs.setSubjectKeyIdentifier(encodedSkid);

        CertStore cs = CertStore.getInstance(
            "Collection",
            new CollectionCertStoreParameters(Collections.singleton(cert)));

        Collection<?> certs = cs.getCertificates(xcs);
        assertFalse(certs.isEmpty());

        XMLX509SKI xmlx509SKI = new XMLX509SKI(TestUtils.newDocument(), skid);
        assertNotNull(xmlx509SKI.getSKIBytes());

        XMLX509SKI xmlx509SKI2 = new XMLX509SKI(TestUtils.newDocument(), cert);
        assertNotNull(xmlx509SKI2.getSKIBytes());

        assertEquals(xmlx509SKI, xmlx509SKI2);
        assertEquals(xmlx509SKI.hashCode(), xmlx509SKI2.hashCode());

    }
}
