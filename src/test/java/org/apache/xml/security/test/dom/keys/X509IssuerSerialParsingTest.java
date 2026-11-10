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
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.x509.XMLX509IssuerSerial;
import org.apache.xml.security.keys.keyresolver.KeyResolverException;
import org.apache.xml.security.keys.keyresolver.implementations.PrivateKeyResolver;
import org.apache.xml.security.keys.storage.StorageResolver;
import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.utils.Constants;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * An attacker-supplied X509SerialNumber is length-bounded before it is parsed (decimal
 * BigInteger parsing is super-linear in the number of digits), and malformed values are reported
 * through the resolvers' declared exception types rather than as an unchecked NumberFormatException.
 */
class X509IssuerSerialParsingTest {

    private static final String DS = Constants.SignatureSpecNS;
    private static final String MAX_LENGTH_SERIAL = "9".repeat(100);
    private static final String TOO_LONG_SERIAL = "9".repeat(101);
    /** A few hundred kilobytes of digits: would cost noticeable CPU if it reached BigInteger. */
    private static final String HUGE_SERIAL = "9".repeat(500_000);

    private static KeyStore keyStore;
    private static X509Certificate certificate;

    @BeforeAll
    static void setUp() throws Exception {
        org.apache.xml.security.Init.init();
        keyStore = XmlSecTestEnvironment.getTestKeyStore();
        certificate = (X509Certificate) keyStore.getCertificate(keyStore.aliases().nextElement());
    }

    static Stream<String> invalidSerialNumbers() {
        return Stream.of("not-a-number", TOO_LONG_SERIAL);
    }

    // ---------------------------------------------------------------- XMLX509IssuerSerial

    @ParameterizedTest
    @ValueSource(strings = {"12345", " 12345 ", "\n  12345\n", "-12345"})
    void testValidSerialNumber(String serial) throws Exception {
        assertEquals(new BigInteger(serial.trim()), issuerSerial("CN=test", serial).getSerialNumber());
    }

    @Test
    void testMaximumLengthSerialNumber() throws Exception {
        assertEquals(new BigInteger(MAX_LENGTH_SERIAL), issuerSerial("CN=test", MAX_LENGTH_SERIAL).getSerialNumber());
    }

    @Test
    void testEqualsAndHashCode() throws Exception {
        XMLX509IssuerSerial a = issuerSerial("CN=test", "12345");
        XMLX509IssuerSerial b = issuerSerial("CN=test", " 12345 ");
        XMLX509IssuerSerial c = issuerSerial("CN=test", "54321");
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertNotEquals(a, c);
    }

    @ParameterizedTest
    @ValueSource(strings = {"not-a-number", "12abc", ""})
    void testNonNumericSerialNumberRejectedOnConstruction(String serial) {
        XMLSecurityException ex = assertThrows(XMLSecurityException.class, () -> issuerSerial("CN=test", serial));
        assertTrue(ex.getCause() instanceof NumberFormatException, String.valueOf(ex.getCause()));
    }

    @Test
    void testTooLongSerialNumberRejectedOnConstructionBeforeParsing() {
        for (String serial : new String[] {TOO_LONG_SERIAL, HUGE_SERIAL}) {
            XMLSecurityException ex = assertThrows(XMLSecurityException.class, () -> issuerSerial("CN=test", serial));
            // Rejected by the length check, not by BigInteger
            assertTrue(ex.getCause() instanceof IllegalArgumentException
                && !(ex.getCause() instanceof NumberFormatException), String.valueOf(ex.getCause()));
        }
    }

    @Test
    void testMissingSerialNumberRejectedOnConstruction() throws Exception {
        Document doc = parse("<ds:X509IssuerSerial xmlns:ds=\"" + DS + "\">"
            + "<ds:X509IssuerName>CN=test</ds:X509IssuerName></ds:X509IssuerSerial>");
        assertThrows(XMLSecurityException.class, () -> new XMLX509IssuerSerial(doc.getDocumentElement(), ""));
    }

    @Test
    void testX509DataItemIssuerSerialRejectsInvalidSerialNumber() throws Exception {
        Document doc = parse("<root xmlns:ds=\"" + DS + "\">" + x509Data("CN=test", TOO_LONG_SERIAL) + "</root>");
        Element x509DataElement = (Element) doc.getElementsByTagNameNS(DS, "X509Data").item(0);
        org.apache.xml.security.keys.content.X509Data x509Data =
            new org.apache.xml.security.keys.content.X509Data(x509DataElement, "");
        assertThrows(XMLSecurityException.class, () -> x509Data.itemIssuerSerial(0));
    }

    // ---------------------------------------------------------------- X509IssuerSerialResolver

    @Test
    void testIssuerSerialResolverMatchesCertificate() throws Exception {
        KeyInfo keyInfo = keyInfoWithStorage(issuerName(), certificate.getSerialNumber().toString());
        assertEquals(certificate, keyInfo.getX509Certificate());
    }

    @ParameterizedTest
    @MethodSource("invalidSerialNumbers")
    void testIssuerSerialResolverRejectsInvalidSerialNumber(String serial) throws Exception {
        KeyInfo keyInfo = keyInfoWithStorage(issuerName(), serial);
        KeyResolverException ex = assertThrows(KeyResolverException.class, keyInfo::getX509Certificate);
        // Reported by the resolver's own XMLSecurityException handling, not the KeyInfo catch-all
        assertTrue(ex.getCause() instanceof XMLSecurityException, String.valueOf(ex.getCause()));
    }

    @Test
    void testIssuerSerialResolverRejectsHugeSerialNumber() throws Exception {
        KeyInfo keyInfo = keyInfoWithStorage(issuerName(), HUGE_SERIAL);
        assertThrows(KeyResolverException.class, keyInfo::getX509Certificate);
    }

    // ---------------------------------------------------------------- PrivateKeyResolver

    @Test
    void testPrivateKeyResolverMatchesKeyEntry() throws Exception {
        KeyInfo keyInfo = keyInfoWithPrivateKeyResolver(issuerName(), certificate.getSerialNumber().toString());
        assertNotNull(keyInfo.getPrivateKey());
    }

    @ParameterizedTest
    @MethodSource("invalidSerialNumbers")
    void testPrivateKeyResolverIgnoresInvalidSerialNumber(String serial) throws Exception {
        KeyInfo keyInfo = keyInfoWithPrivateKeyResolver(issuerName(), serial);
        assertNull(keyInfo.getPrivateKey());
    }

    // ---------------------------------------------------------------- JSR-105

    @Test
    void testJSR105ValidSerialNumber() throws Exception {
        X509IssuerSerial issuerSerial = unmarshalIssuerSerial(" 12345 ");
        assertEquals(BigInteger.valueOf(12345), issuerSerial.getSerialNumber());
    }

    @ParameterizedTest
    @MethodSource("invalidSerialNumbers")
    void testJSR105RejectsInvalidSerialNumber(String serial) {
        assertThrows(MarshalException.class, () -> unmarshalIssuerSerial(serial));
    }

    @Test
    void testJSR105RejectsHugeSerialNumber() {
        MarshalException ex = assertThrows(MarshalException.class, () -> unmarshalIssuerSerial(HUGE_SERIAL));
        assertTrue(ex.getMessage().contains("maximum length"), ex.getMessage());
    }

    // ---------------------------------------------------------------- helpers

    private static String issuerName() {
        return certificate.getIssuerX500Principal().getName();
    }

    private static String x509Data(String issuerName, String serial) {
        return "<ds:X509Data><ds:X509IssuerSerial>"
            + "<ds:X509IssuerName>" + issuerName + "</ds:X509IssuerName>"
            + "<ds:X509SerialNumber>" + serial + "</ds:X509SerialNumber>"
            + "</ds:X509IssuerSerial></ds:X509Data>";
    }

    private static XMLX509IssuerSerial issuerSerial(String issuerName, String serial) throws Exception {
        Document doc = parse("<ds:X509IssuerSerial xmlns:ds=\"" + DS + "\">"
            + "<ds:X509IssuerName>" + issuerName + "</ds:X509IssuerName>"
            + "<ds:X509SerialNumber>" + serial + "</ds:X509SerialNumber></ds:X509IssuerSerial>");
        return new XMLX509IssuerSerial(doc.getDocumentElement(), "");
    }

    private static KeyInfo keyInfo(String issuerName, String serial) throws Exception {
        Document doc = parse("<ds:KeyInfo xmlns:ds=\"" + DS + "\">" + x509Data(issuerName, serial) + "</ds:KeyInfo>");
        KeyInfo keyInfo = new KeyInfo(doc.getDocumentElement(), "");
        keyInfo.setSecureValidation(true);
        return keyInfo;
    }

    private static KeyInfo keyInfoWithStorage(String issuerName, String serial) throws Exception {
        KeyInfo keyInfo = keyInfo(issuerName, serial);
        keyInfo.addStorageResolver(new StorageResolver(keyStore));
        return keyInfo;
    }

    private static KeyInfo keyInfoWithPrivateKeyResolver(String issuerName, String serial) throws Exception {
        KeyInfo keyInfo = keyInfo(issuerName, serial);
        keyInfo.registerInternalKeyResolver(
            new PrivateKeyResolver(keyStore, XmlSecTestEnvironment.TEST_KS_PASSWORD.toCharArray()));
        return keyInfo;
    }

    private static X509IssuerSerial unmarshalIssuerSerial(String serial) throws Exception {
        Document doc = parse("<ds:KeyInfo xmlns:ds=\"" + DS + "\">" + x509Data("CN=test", serial) + "</ds:KeyInfo>");
        javax.xml.crypto.dsig.keyinfo.KeyInfo keyInfo = KeyInfoFactory.getInstance("DOM",
            new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI()).unmarshalKeyInfo(new DOMStructure(doc.getDocumentElement()));
        X509Data x509Data = (X509Data) keyInfo.getContent().get(0);
        return (X509IssuerSerial) x509Data.getContent().get(0);
    }

    private static Document parse(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }
}
