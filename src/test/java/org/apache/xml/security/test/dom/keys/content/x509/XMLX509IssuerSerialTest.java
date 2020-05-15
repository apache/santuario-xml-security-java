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


import org.apache.xml.security.keys.content.x509.XMLX509IssuerSerial;
import org.apache.xml.security.test.dom.TestUtils;
import org.w3c.dom.Document;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * XMLX509IssuerSerial tests.
 *
 */
public class XMLX509IssuerSerialTest {

    private Document doc;

    public XMLX509IssuerSerialTest() throws Exception {
        doc = TestUtils.newDocument();
    }

    @org.junit.jupiter.api.Test
    public void testGetIssuerName() throws Exception {
        // Make sure hex encoded value is not escaped (see ...)
        String issuer = "9.99.999=#abc123";
        XMLX509IssuerSerial is =
            new XMLX509IssuerSerial(doc, issuer, 0);
        assertEquals(issuer, is.getIssuerName());
        // System.out.println(is.getIssuerName());
        issuer = "CN=#abc123";
        is = new XMLX509IssuerSerial(doc, issuer, 0);
        assertEquals("CN=\\#abc123", is.getIssuerName());
        // System.out.println(is.getIssuerName());
    }

    @org.junit.jupiter.api.Test
    public void testEqualsHashcode() throws Exception {
        XMLX509IssuerSerial is1 = new XMLX509IssuerSerial(doc, "1234", 0);
        assertEquals("1234", is1.getIssuerName());

        XMLX509IssuerSerial is2 = new XMLX509IssuerSerial(doc, "1234", 0);
        assertEquals("1234", is2.getIssuerName());

        assertEquals(is1, is2);
        assertEquals(is1.hashCode(), is2.hashCode());
    }
}