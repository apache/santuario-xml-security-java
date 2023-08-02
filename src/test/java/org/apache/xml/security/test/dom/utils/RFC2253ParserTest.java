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
package org.apache.xml.security.test.dom.utils;

import org.apache.xml.security.utils.RFC2253Parser;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 */
class RFC2253ParserTest {

    @Test
    void testToXML1() throws Exception {
        assertEquals(RFC2253Parser.rfc2253toXMLdsig("CN=\"Steve, Kille\",  O=Isode Limited, C=GB"), "CN=Steve\\, Kille,O=Isode Limited,C=GB");
    }

    @Test
    void testToXML2() throws Exception {
        assertEquals(RFC2253Parser.rfc2253toXMLdsig("CN=Steve Kille    ,   O=Isode Limited,C=GB"), "CN=Steve Kille,O=Isode Limited,C=GB");
    }

    @Test
    void testToXML3() throws Exception {
        assertEquals(RFC2253Parser.rfc2253toXMLdsig("\\ OU=Sales+CN=J. Smith,O=Widget Inc.,C=US\\ \\ "), "\\20OU=Sales+CN=J. Smith,O=Widget Inc.,C=US\\20\\20");
    }

    @Test
    void testToXML4() throws Exception {
        assertEquals(RFC2253Parser.rfc2253toXMLdsig("CN=L. Eagle,O=Sue\\, Grabbit and Runn,C=GB"), "CN=L. Eagle,O=Sue\\, Grabbit and Runn,C=GB");
    }

    @Test
    void testToXML5() throws Exception {
        assertEquals(RFC2253Parser.rfc2253toXMLdsig("CN=Before\\0DAfter,O=Test,C=GB"), "CN=Before\\0DAfter,O=Test,C=GB");
    }

    @Test
    void testToXML6() throws Exception {
        assertEquals(RFC2253Parser.rfc2253toXMLdsig("CN=\"L. Eagle,O=Sue, = + < > # ;Grabbit and Runn\",C=GB"), "CN=L. Eagle\\,O\\=Sue\\, \\= \\+ \\< \\> \\# \\;Grabbit and Runn,C=GB");
    }

    @Test
    void testToXML7() throws Exception {
        assertEquals(RFC2253Parser.rfc2253toXMLdsig("1.3.6.1.4.1.1466.0=#04024869,O=Test,C=GB"), "1.3.6.1.4.1.1466.0=#04024869,O=Test,C=GB");
    }

    @Test
    void testToXML8() throws Exception {
        StringBuilder sb = new StringBuilder("Lu\uc48di\uc487");
        assertEquals(RFC2253Parser.rfc2253toXMLdsig("SN=" + sb.toString()), "SN=Lu\uc48di\uc487");
    }

    @Test
    void testToRFC1() throws Exception {
        assertEquals(RFC2253Parser.xmldsigtoRFC2253("CN=\"Steve, Kille\",  O=Isode Limited, C=GB"), "CN=Steve\\, Kille,O=Isode Limited,C=GB");
    }

    @Test
    void testToRFC2() throws Exception {
        assertEquals(RFC2253Parser.xmldsigtoRFC2253("CN=Steve Kille    ,   O=Isode Limited,C=GB"), "CN=Steve Kille,O=Isode Limited,C=GB");
    }

    @Test
    void testToRFC3() throws Exception {
        assertEquals(RFC2253Parser.xmldsigtoRFC2253("\\20OU=Sales+CN=J. Smith,O=Widget Inc.,C=US\\20\\20 "), "\\ OU=Sales+CN=J. Smith,O=Widget Inc.,C=US\\ \\ ");
    }

    @Test
    void testToRFC4() throws Exception {
        assertEquals(RFC2253Parser.xmldsigtoRFC2253("CN=L. Eagle,O=Sue\\, Grabbit and Runn,C=GB"), "CN=L. Eagle,O=Sue\\, Grabbit and Runn,C=GB");
    }

    @Test
    void testToRFC5() throws Exception {
        assertEquals(RFC2253Parser.xmldsigtoRFC2253("CN=Before\\12After,O=Test,C=GB"), "CN=Before\\\u0012After,O=Test,C=GB");
    }

    @Test
    void testToRFC6() throws Exception {
        assertEquals(RFC2253Parser.xmldsigtoRFC2253("CN=\"L. Eagle,O=Sue, = + < > # ;Grabbit and Runn\",C=GB"), "CN=L. Eagle\\,O\\=Sue\\, \\= \\+ \\< \\> \\# \\;Grabbit and Runn,C=GB");
    }

    @Test
    void testToRFC7() throws Exception {
        assertEquals(RFC2253Parser.xmldsigtoRFC2253("1.3.6.1.4.1.1466.0=\\#04024869,O=Test,C=GB"), "1.3.6.1.4.1.1466.0=\\#04024869,O=Test,C=GB");
    }

    @Test
    void testToRFC8() throws Exception {
        StringBuilder sb = new StringBuilder("Lu\uc48di\uc487");
        assertEquals(RFC2253Parser.xmldsigtoRFC2253("SN=" + sb.toString()), "SN=Lu\uc48di\uc487");
    }
}