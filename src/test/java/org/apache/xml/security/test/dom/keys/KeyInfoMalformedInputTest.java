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
package org.apache.xml.security.test.dom.keys;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.keyvalues.DSAKeyValue;
import org.apache.xml.security.keys.content.keyvalues.ECKeyValue;
import org.apache.xml.security.keys.content.keyvalues.RSAKeyValue;
import org.apache.xml.security.keys.keyresolver.KeyResolverException;
import org.apache.xml.security.keys.storage.StorageResolver;
import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.utils.Constants;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Malformed values in an (untrusted) ds:KeyInfo must not escape the KeyInfo / KeyValue API as
 * unchecked exceptions. Depending on the resolver, malformed content is either reported as a
 * {@link KeyResolverException} or treated as "no key resolved" (null), as was already the case for
 * e.g. an invalid RSA key specification.
 */
class KeyInfoMalformedInputTest {

    private static final String DS = Constants.SignatureSpecNS;
    private static final String DSIG11 = Constants.SignatureSpec11NS;
    /** Rejected by the MIME base64 decoder ("Last unit does not have enough valid bits"). */
    private static final String BAD_BASE64 = "A";

    private static final String RSA_KEY_VALUE =
        "<ds:KeyValue><ds:RSAKeyValue><ds:Modulus>" + BAD_BASE64 + "</ds:Modulus>"
        + "<ds:Exponent>AQAB</ds:Exponent></ds:RSAKeyValue></ds:KeyValue>";
    private static final String DSA_KEY_VALUE =
        "<ds:KeyValue><ds:DSAKeyValue><ds:P>" + BAD_BASE64 + "</ds:P><ds:Q>AQAB</ds:Q>"
        + "<ds:G>AQAB</ds:G><ds:Y>AQAB</ds:Y></ds:DSAKeyValue></ds:KeyValue>";
    private static final String EC_KEY_VALUE =
        "<ds:KeyValue><dsig11:ECKeyValue><dsig11:NamedCurve URI=\"urn:oid:1.2.840.10045.3.1.7\"/>"
        + "<dsig11:PublicKey>" + BAD_BASE64 + "</dsig11:PublicKey></dsig11:ECKeyValue></ds:KeyValue>";

    @BeforeAll
    static void setUp() {
        org.apache.xml.security.Init.init();
    }

    @Test
    void testMalformedKeyValuesResolveToNoKey() throws Exception {
        assertNull(keyInfo(RSA_KEY_VALUE).getPublicKey());
        assertNull(keyInfo(DSA_KEY_VALUE).getPublicKey());
        assertNull(keyInfo(EC_KEY_VALUE).getPublicKey());
        assertNull(keyInfo("<dsig11:DEREncodedKeyValue>" + BAD_BASE64 + "</dsig11:DEREncodedKeyValue>").getPublicKey());
    }

    @Test
    void testMalformedKeyValuesDirectly() throws Exception {
        assertThrows(XMLSecurityException.class,
            () -> new RSAKeyValue(firstElement(RSA_KEY_VALUE, DS, "RSAKeyValue"), "").getPublicKey());
        assertThrows(XMLSecurityException.class,
            () -> new DSAKeyValue(firstElement(DSA_KEY_VALUE, DS, "DSAKeyValue"), "").getPublicKey());
        assertThrows(XMLSecurityException.class,
            () -> new ECKeyValue(firstElement(EC_KEY_VALUE, DSIG11, "ECKeyValue"), "").getPublicKey());
    }

    @Test
    void testMalformedX509Certificate() throws Exception {
        KeyInfo keyInfo = keyInfo("<ds:X509Data><ds:X509Certificate>" + BAD_BASE64 + "</ds:X509Certificate></ds:X509Data>");
        assertThrows(KeyResolverException.class, keyInfo::getX509Certificate);
    }

    @Test
    void testNonNumericX509SerialNumber() throws Exception {
        // The IssuerSerial resolver only parses the serial number when it has certificates to compare against
        KeyInfo keyInfo = keyInfo("<ds:X509Data><ds:X509IssuerSerial>"
            + "<ds:X509IssuerName>CN=test</ds:X509IssuerName>"
            + "<ds:X509SerialNumber>not-a-number</ds:X509SerialNumber>"
            + "</ds:X509IssuerSerial></ds:X509Data>");
        keyInfo.addStorageResolver(new StorageResolver(XmlSecTestEnvironment.getTestKeyStore()));
        assertThrows(KeyResolverException.class, keyInfo::getX509Certificate);
        assertThrows(KeyResolverException.class, keyInfo::getPublicKey);
    }

    private static KeyInfo keyInfo(String content) throws Exception {
        Document doc = parse("<ds:KeyInfo xmlns:ds=\"" + DS + "\" xmlns:dsig11=\"" + DSIG11 + "\">"
            + content + "</ds:KeyInfo>");
        KeyInfo keyInfo = new KeyInfo(doc.getDocumentElement(), "");
        keyInfo.setSecureValidation(true);
        return keyInfo;
    }

    private static Element firstElement(String content, String namespace, String localName) throws Exception {
        Document doc = parse("<root xmlns:ds=\"" + DS + "\" xmlns:dsig11=\"" + DSIG11 + "\">" + content + "</root>");
        return (Element) doc.getElementsByTagNameNS(namespace, localName).item(0);
    }

    private static Document parse(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }
}
