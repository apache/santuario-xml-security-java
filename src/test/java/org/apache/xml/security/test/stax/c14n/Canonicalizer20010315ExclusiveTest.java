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
package org.apache.xml.security.test.stax.c14n;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.transformer.canonicalizer.Canonicalizer20010315_Excl;
import org.apache.xml.security.stax.impl.transformer.canonicalizer.Canonicalizer20010315_ExclOmitCommentsTransformer;
import org.apache.xml.security.stax.impl.transformer.canonicalizer.Canonicalizer20010315_ExclWithCommentsTransformer;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.test.stax.utils.XMLSecEventAllocator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 */
public class Canonicalizer20010315ExclusiveTest {

    private XMLInputFactory xmlInputFactory;

    @BeforeEach
    public void setUp() throws Exception {
        this.xmlInputFactory = XMLInputFactory.newInstance();
        this.xmlInputFactory.setEventAllocator(new XMLSecEventAllocator());
    }

    @Test
    public void test221excl() throws Exception {

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final Canonicalizer20010315_ExclWithCommentsTransformer c = new Canonicalizer20010315_ExclWithCommentsTransformer();
        c.setOutputStream(baos);
        final XMLEventReader xmlSecEventReader = xmlInputFactory.createXMLEventReader(
                this.getClass().getClassLoader().getResourceAsStream(
                    "org/apache/xml/security/c14n/inExcl/example2_2_1.xml")
        );

        XMLSecEvent xmlSecEvent = null;
        while (xmlSecEventReader.hasNext()) {
            xmlSecEvent = (XMLSecEvent) xmlSecEventReader.nextEvent();
            if (xmlSecEvent.isStartElement() && xmlSecEvent.asStartElement().getName().equals(new QName("http://example.net", "elem2"))) {
                break;
            }
        }
        while (xmlSecEventReader.hasNext()) {

            c.transform(xmlSecEvent);

            if (xmlSecEvent.isEndElement() && xmlSecEvent.asEndElement().getName().equals(new QName("http://example.net", "elem2"))) {
                break;
            }
            xmlSecEvent = (XMLSecEvent) xmlSecEventReader.nextEvent();
        }

        final byte[] reference =
            getBytesFromResource(this.getClass().getClassLoader().getResource(
                "org/apache/xml/security/c14n/inExcl/example2_2_c14nized_exclusive.xml"));
        final boolean equals = java.security.MessageDigest.isEqual(reference, baos.toByteArray());

        if (!equals) {
            System.out.println("Expected:\n" + new String(reference, java.nio.charset.StandardCharsets.UTF_8));
            System.out.println("");
            System.out.println("Got:\n" + new String(baos.toByteArray(), java.nio.charset.StandardCharsets.UTF_8));
        }

        assertTrue(equals);
    }

    @Test
    public void test222excl() throws Exception {

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final Canonicalizer20010315_ExclWithCommentsTransformer c = new Canonicalizer20010315_ExclWithCommentsTransformer();
        c.setOutputStream(baos);

        canonicalize(c,
                this.getClass().getClassLoader().getResourceAsStream(
                    "org/apache/xml/security/c14n/inExcl/example2_2_2.xml"),
                new QName("http://example.net", "elem2")
        );

        final byte[] reference =
            getBytesFromResource(this.getClass().getClassLoader().getResource(
                "org/apache/xml/security/c14n/inExcl/example2_2_c14nized_exclusive.xml"));
        final boolean equals = java.security.MessageDigest.isEqual(reference, baos.toByteArray());

        if (!equals) {
            System.out.println("Expected:\n" + new String(reference, java.nio.charset.StandardCharsets.UTF_8));
            System.out.println("");
            System.out.println("Got:\n" + new String(baos.toByteArray(), java.nio.charset.StandardCharsets.UTF_8));
        }

        assertTrue(equals);
    }

    @Test
    public void test24excl() throws Exception {

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final Canonicalizer20010315_ExclWithCommentsTransformer c = new Canonicalizer20010315_ExclWithCommentsTransformer();
        c.setOutputStream(baos);

        canonicalize(c,
                this.getClass().getClassLoader().getResourceAsStream(
                        "org/apache/xml/security/c14n/inExcl/example2_4.xml"),
                new QName("http://example.net", "elem2")
        );

        final byte[] reference =
            getBytesFromResource(this.getClass().getClassLoader().getResource(
                "org/apache/xml/security/c14n/inExcl/example2_4_c14nized.xml"));
        final boolean equals = java.security.MessageDigest.isEqual(reference, baos.toByteArray());

        if (!equals) {
            System.out.println("Expected:\n" + new String(reference, java.nio.charset.StandardCharsets.UTF_8));
            System.out.println("");
            System.out.println("Got:\n" + new String(baos.toByteArray(), java.nio.charset.StandardCharsets.UTF_8));
        }

        assertTrue(equals);
    }

    @Test
    public void testComplexDocexcl() throws Exception {

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final Canonicalizer20010315_ExclWithCommentsTransformer c = new Canonicalizer20010315_ExclWithCommentsTransformer();
        c.setOutputStream(baos);

        canonicalize(c,
                this.getClass().getClassLoader().getResourceAsStream(
                        "org/apache/xml/security/c14n/inExcl/plain-soap-1.1.xml"),
                new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body", "env")
        );

        final byte[] reference =
            getBytesFromResource(this.getClass().getClassLoader().getResource(
                "org/apache/xml/security/c14n/inExcl/plain-soap-c14nized.xml"));
        final boolean equals = java.security.MessageDigest.isEqual(reference, baos.toByteArray());

        if (!equals) {
            System.out.println("Expected:\n" + new String(reference, java.nio.charset.StandardCharsets.UTF_8));
            System.out.println("");
            System.out.println("Got:\n" + new String(baos.toByteArray(), java.nio.charset.StandardCharsets.UTF_8));
        }
        assertTrue(equals);
    }

    @Test
    public void testNodeSet() throws Exception {

        final String XML =
                "<env:Envelope"
                        + " xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\""
                        + " xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\""
                        + " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
                        + " xmlns:ns0=\"http://xmlsoap.org/Ping\""
                        + " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
                        + "<env:Body wsu:Id=\"body\">"
                        + "<ns0:Ping xsi:type=\"ns0:ping\">"
                        + "<ns0:text xsi:type=\"xsd:string\">hello</ns0:text>"
                        + "</ns0:Ping>"
                        + "</env:Body>"
                        + "</env:Envelope>";

        final String c14nXML =
                "<env:Body"
                        + " xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\""
                        + " xmlns:ns0=\"http://xmlsoap.org/Ping\""
                        + " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\""
                        + " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
                        + " wsu:Id=\"body\">"
                        + "<ns0:Ping xsi:type=\"ns0:ping\">"
                        + "<ns0:text xsi:type=\"xsd:string\">hello</ns0:text>"
                        + "</ns0:Ping>"
                        + "</env:Body>";

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final List<String> inclusiveNamespaces = new ArrayList<>();
        inclusiveNamespaces.add("env");
        inclusiveNamespaces.add("ns0");
        inclusiveNamespaces.add("xsi");
        inclusiveNamespaces.add("wsu");
        final Canonicalizer20010315_ExclOmitCommentsTransformer c = new Canonicalizer20010315_ExclOmitCommentsTransformer();
        final Map<String, Object> transformerProperties = new HashMap<>();
        transformerProperties.put(Canonicalizer20010315_Excl.INCLUSIVE_NAMESPACES_PREFIX_LIST, inclusiveNamespaces);
        c.setProperties(transformerProperties);
        c.setOutputStream(baos);

        canonicalize(c, new StringReader(XML), new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"));

        assertEquals(new String(baos.toByteArray(), java.nio.charset.StandardCharsets.UTF_8), c14nXML);
    }

    /**
     * Method test24Aexcl - a testcase for SANTUARIO-263
     * "Canonicalizer can't handle dynamical created DOM correctly"
     * https://issues.apache.org/jira/browse/SANTUARIO-263
     */
    @Test
    public void test24Aexcl() throws Exception {
        final Document doc = TestUtils.newDocument();
        final Element local = doc.createElementNS("foo:bar", "dsig:local");
        final Element test = doc.createElementNS("http://example.net", "etsi:test");
        final Element elem2 = doc.createElementNS("http://example.net", "etsi:elem2");
        final Element stuff = doc.createElementNS("foo:bar", "dsig:stuff");
        elem2.appendChild(stuff);
        test.appendChild(elem2);
        local.appendChild(test);
        doc.appendChild(local);

        final TransformerFactory tf = TransformerFactory.newInstance();
        final Transformer t = tf.newTransformer();
        final StringWriter stringWriter = new StringWriter();
        final StreamResult streamResult = new StreamResult(stringWriter);
        t.transform(new DOMSource(doc), streamResult);

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final List<String> inclusiveNamespaces = new ArrayList<>();
        final Canonicalizer20010315_ExclWithCommentsTransformer c =
                new Canonicalizer20010315_ExclWithCommentsTransformer();
        final Map<String, Object> transformerProperties = new HashMap<>();
        transformerProperties.put(Canonicalizer20010315_Excl.INCLUSIVE_NAMESPACES_PREFIX_LIST, inclusiveNamespaces);
        c.setProperties(transformerProperties);
        c.setOutputStream(baos);

        canonicalize(c, new StringReader(stringWriter.toString()), new QName("http://example.net", "elem2"));

        final byte[] reference =
                getBytesFromResource(this.getClass().getClassLoader().getResource(
                    "org/apache/xml/security/c14n/inExcl/example2_4_c14nized.xml"));
        final boolean equals = java.security.MessageDigest.isEqual(reference, baos.toByteArray());

        assertTrue(equals);
    }

    /**
     * Test default namespace behavior if its in the InclusiveNamespace prefix list.
     *
     * @throws Exception
     */
    @Test
    public void testDefaultNSInInclusiveNamespacePrefixList1() throws Exception {
        final String XML =
                "<env:Envelope"
                        + " xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\""
                        + " xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\""
                        + " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
                        + " xmlns:ns0=\"http://xmlsoap.org/Ping\""
                        + " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
                        + "<env:Body wsu:Id=\"body\">"
                        + "<ns0:Ping xsi:type=\"ns0:ping\">"
                        + "<ns0:text xsi:type=\"xsd:string\">hello</ns0:text>"
                        + "</ns0:Ping>"
                        + "</env:Body>"
                        + "</env:Envelope>";

        final String c14nXML =
                "<env:Body"
                        + " xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\""
                        + " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\""
                        + " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
                        + " wsu:Id=\"body\">"
                        + "<ns0:Ping xmlns:ns0=\"http://xmlsoap.org/Ping\" xsi:type=\"ns0:ping\">"
                        + "<ns0:text xsi:type=\"xsd:string\">hello</ns0:text>"
                        + "</ns0:Ping>"
                        + "</env:Body>";

        {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final List<String> inclusiveNamespaces = new ArrayList<>();
            inclusiveNamespaces.add("#default");
            inclusiveNamespaces.add("xsi");
            final Canonicalizer20010315_ExclOmitCommentsTransformer c = new Canonicalizer20010315_ExclOmitCommentsTransformer();
            final Map<String, Object> transformerProperties = new HashMap<>();
            transformerProperties.put(Canonicalizer20010315_Excl.INCLUSIVE_NAMESPACES_PREFIX_LIST, inclusiveNamespaces);
            c.setProperties(transformerProperties);
            c.setOutputStream(baos);
            canonicalize(c, new StringReader(XML), new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"));

            assertEquals(new String(baos.toByteArray(), java.nio.charset.StandardCharsets.UTF_8), c14nXML);
        }

        {
            //exactly the same outcome is expected if #default is not set:
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final List<String> inclusiveNamespaces = new ArrayList<>();
            inclusiveNamespaces.add("xsi");
            final Canonicalizer20010315_ExclOmitCommentsTransformer c = new Canonicalizer20010315_ExclOmitCommentsTransformer();
            final Map<String, Object> transformerProperties = new HashMap<>();
            transformerProperties.put(Canonicalizer20010315_Excl.INCLUSIVE_NAMESPACES_PREFIX_LIST, inclusiveNamespaces);
            c.setProperties(transformerProperties);
            c.setOutputStream(baos);
            canonicalize(c, new StringReader(XML), new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"));

            assertEquals(new String(baos.toByteArray(), java.nio.charset.StandardCharsets.UTF_8), c14nXML);
        }
    }

    /**
     * Test default namespace behavior if its in the InclusiveNamespace prefix list.
     *
     * @throws Exception
     */
    @Test
    public void testDefaultNSInInclusiveNamespacePrefixList2() throws Exception {
        final String XML =
                "<env:Envelope"
                        + " xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\""
                        + " xmlns=\"http://example.com\""
                        + " xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\""
                        + " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
                        + " xmlns:ns0=\"http://xmlsoap.org/Ping\""
                        + " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
                        + "<env:Body wsu:Id=\"body\">"
                        + "<ns0:Ping xsi:type=\"ns0:ping\">"
                        + "<ns0:text xmlns=\"\" xsi:type=\"xsd:string\">hello</ns0:text>"
                        + "</ns0:Ping>"
                        + "</env:Body>"
                        + "</env:Envelope>";

        final String c14nXML1 =
                "<env:Body"
                        + " xmlns=\"http://example.com\""
                        + " xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\""
                        + " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\""
                        + " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
                        + " wsu:Id=\"body\">"
                        + "<ns0:Ping xmlns:ns0=\"http://xmlsoap.org/Ping\" xsi:type=\"ns0:ping\">"
                        + "<ns0:text xmlns=\"\" xsi:type=\"xsd:string\">hello</ns0:text>"
                        + "</ns0:Ping>"
                        + "</env:Body>";

        final String c14nXML2 =
                "<env:Body"
                        + " xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\""
                        + " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\""
                        + " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
                        + " wsu:Id=\"body\">"
                        + "<ns0:Ping xmlns:ns0=\"http://xmlsoap.org/Ping\" xsi:type=\"ns0:ping\">"
                        + "<ns0:text xsi:type=\"xsd:string\">hello</ns0:text>"
                        + "</ns0:Ping>"
                        + "</env:Body>";

        {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final List<String> inclusiveNamespaces = new ArrayList<>();
            inclusiveNamespaces.add("#default");
            inclusiveNamespaces.add("xsi");
            final Canonicalizer20010315_ExclOmitCommentsTransformer c = new Canonicalizer20010315_ExclOmitCommentsTransformer();
            final Map<String, Object> transformerProperties = new HashMap<>();
            transformerProperties.put(Canonicalizer20010315_Excl.INCLUSIVE_NAMESPACES_PREFIX_LIST, inclusiveNamespaces);
            c.setProperties(transformerProperties);
            c.setOutputStream(baos);
            canonicalize(c, new StringReader(XML), new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"));

            assertEquals(new String(baos.toByteArray(), java.nio.charset.StandardCharsets.UTF_8), c14nXML1);
        }
        {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final List<String> inclusiveNamespaces = new ArrayList<>();
            inclusiveNamespaces.add("xsi");
            final Canonicalizer20010315_ExclOmitCommentsTransformer c = new Canonicalizer20010315_ExclOmitCommentsTransformer();
            final Map<String, Object> transformerProperties = new HashMap<>();
            transformerProperties.put(Canonicalizer20010315_Excl.INCLUSIVE_NAMESPACES_PREFIX_LIST, inclusiveNamespaces);
            c.setProperties(transformerProperties);
            c.setOutputStream(baos);
            canonicalize(c, new StringReader(XML), new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"));

            assertEquals(new String(baos.toByteArray(), java.nio.charset.StandardCharsets.UTF_8), c14nXML2);
        }
    }

    /**
     * Test default namespace behavior if its in the InclusiveNamespace prefix list.
     *
     * @throws Exception
     */
    @Test
    public void testDefaultNSInInclusiveNamespacePrefixList3() throws Exception {
        final String XML =
                "<env:Envelope"
                        + " xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\""
                        + " xmlns=\"\""
                        + " xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\""
                        + " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
                        + " xmlns:ns0=\"http://xmlsoap.org/Ping\""
                        + " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
                        + "<env:Body wsu:Id=\"body\">"
                        + "<ns0:Ping xsi:type=\"ns0:ping\">"
                        + "<ns0:text xsi:type=\"xsd:string\">hello</ns0:text>"
                        + "</ns0:Ping>"
                        + "</env:Body>"
                        + "</env:Envelope>";

        final String c14nXML =
                "<env:Body"
                        + " xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\""
                        + " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\""
                        + " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
                        + " wsu:Id=\"body\">"
                        + "<ns0:Ping xmlns:ns0=\"http://xmlsoap.org/Ping\" xsi:type=\"ns0:ping\">"
                        + "<ns0:text xsi:type=\"xsd:string\">hello</ns0:text>"
                        + "</ns0:Ping>"
                        + "</env:Body>";

        {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final List<String> inclusiveNamespaces = new ArrayList<>();
            inclusiveNamespaces.add("#default");
            inclusiveNamespaces.add("xsi");
            final Canonicalizer20010315_ExclOmitCommentsTransformer c = new Canonicalizer20010315_ExclOmitCommentsTransformer();
            final Map<String, Object> transformerProperties = new HashMap<>();
            transformerProperties.put(Canonicalizer20010315_Excl.INCLUSIVE_NAMESPACES_PREFIX_LIST, inclusiveNamespaces);
            c.setProperties(transformerProperties);
            c.setOutputStream(baos);
            canonicalize(c, new StringReader(XML), new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"));

            assertEquals(new String(baos.toByteArray(), java.nio.charset.StandardCharsets.UTF_8), c14nXML);
        }
        {
            //exactly the same outcome is expected if #default is not set:
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final List<String> inclusiveNamespaces = new ArrayList<>();
            inclusiveNamespaces.add("xsi");
            final Canonicalizer20010315_ExclOmitCommentsTransformer c = new Canonicalizer20010315_ExclOmitCommentsTransformer();
            final Map<String, Object> transformerProperties = new HashMap<>();
            transformerProperties.put(Canonicalizer20010315_Excl.INCLUSIVE_NAMESPACES_PREFIX_LIST, inclusiveNamespaces);
            c.setProperties(transformerProperties);
            c.setOutputStream(baos);
            canonicalize(c, new StringReader(XML), new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"));

            assertEquals(new String(baos.toByteArray(), java.nio.charset.StandardCharsets.UTF_8), c14nXML);
        }
    }

    /**
     * Test default namespace behavior if its in the InclusiveNamespace prefix list.
     *
     * @throws Exception
     */
    @Test
    public void testDefaultNSInInclusiveNamespacePrefixList4() throws Exception {
        final String XML =
                "<env:Envelope"
                        + " xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\""
                        + " xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\""
                        + " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
                        + " xmlns:ns0=\"http://xmlsoap.org/Ping\""
                        + " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
                        + "<env:Body wsu:Id=\"body\">"
                        + "<ns0:Ping xsi:type=\"ns0:ping\">"
                        + "<ns0:text xmlns=\"\" xsi:type=\"xsd:string\">hello</ns0:text>"
                        + "</ns0:Ping>"
                        + "</env:Body>"
                        + "</env:Envelope>";

        final String c14nXML =
                "<env:Body"
                        + " xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\""
                        + " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\""
                        + " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
                        + " wsu:Id=\"body\">"
                        + "<ns0:Ping xmlns:ns0=\"http://xmlsoap.org/Ping\" xsi:type=\"ns0:ping\">"
                        + "<ns0:text xsi:type=\"xsd:string\">hello</ns0:text>"
                        + "</ns0:Ping>"
                        + "</env:Body>";


        {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final List<String> inclusiveNamespaces = new ArrayList<>();
            inclusiveNamespaces.add("#default");
            inclusiveNamespaces.add("xsi");
            final Canonicalizer20010315_ExclOmitCommentsTransformer c = new Canonicalizer20010315_ExclOmitCommentsTransformer();
            final Map<String, Object> transformerProperties = new HashMap<>();
            transformerProperties.put(Canonicalizer20010315_Excl.INCLUSIVE_NAMESPACES_PREFIX_LIST, inclusiveNamespaces);
            c.setProperties(transformerProperties);
            c.setOutputStream(baos);
            canonicalize(c, new StringReader(XML), new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"));

            assertEquals(new String(baos.toByteArray(), java.nio.charset.StandardCharsets.UTF_8), c14nXML);
        }
        {
            //exactly the same outcome is expected if #default is not set:
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final List<String> inclusiveNamespaces = new ArrayList<>();
            inclusiveNamespaces.add("xsi");
            final Canonicalizer20010315_ExclOmitCommentsTransformer c = new Canonicalizer20010315_ExclOmitCommentsTransformer();
            final Map<String, Object> transformerProperties = new HashMap<>();
            transformerProperties.put(Canonicalizer20010315_Excl.INCLUSIVE_NAMESPACES_PREFIX_LIST, inclusiveNamespaces);
            c.setProperties(transformerProperties);
            c.setOutputStream(baos);
            canonicalize(c, new StringReader(XML), new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"));

            assertEquals(new String(baos.toByteArray(), java.nio.charset.StandardCharsets.UTF_8), c14nXML);
        }
    }

    /**
     * Test default namespace behavior if its in the InclusiveNamespace prefix list.
     *
     * @throws Exception
     */
    @Test
    public void testPropagateDefaultNs1() throws Exception {
        final String XML =
                "<env:Envelope"
                        + " xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\""
                        + " xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\""
                        + " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
                        + " xmlns:ns0=\"http://xmlsoap.org/Ping\""
                        + " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
                        + "<env:Body wsu:Id=\"body\">"
                        + "<ns0:Ping xsi:type=\"ns0:ping\">"
                        + "<ns0:text xsi:type=\"xsd:string\">hello</ns0:text>"
                        + "</ns0:Ping>"
                        + "</env:Body>"
                        + "</env:Envelope>";

        final String c14nXML =
                "<env:Body"
                        + " xmlns=\"\""
                        + " xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\""
                        + " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\""
                        + " wsu:Id=\"body\">"
                        + "<ns0:Ping xmlns:ns0=\"http://xmlsoap.org/Ping\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ns0:ping\">"
                        + "<ns0:text xsi:type=\"xsd:string\">hello</ns0:text>"
                        + "</ns0:Ping>"
                        + "</env:Body>";

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final List<String> inclusiveNamespaces = new ArrayList<>();
        inclusiveNamespaces.add("#default");
        final Canonicalizer20010315_ExclOmitCommentsTransformer c = new Canonicalizer20010315_ExclOmitCommentsTransformer();
        final Map<String, Object> transformerProperties = new HashMap<>();
        transformerProperties.put(Canonicalizer20010315_Excl.INCLUSIVE_NAMESPACES_PREFIX_LIST, inclusiveNamespaces);
        transformerProperties.put(Canonicalizer20010315_Excl.PROPAGATE_DEFAULT_NAMESPACE, Boolean.TRUE);
        c.setProperties(transformerProperties);
        c.setOutputStream(baos);
        canonicalize(c, new StringReader(XML), new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"));

        assertEquals(new String(baos.toByteArray(), java.nio.charset.StandardCharsets.UTF_8), c14nXML);
    }

    @Test
    public void testPropagateDefaultNs2() throws Exception {
        final String XML =
                "<env:Envelope"
                        + " xmlns=\"http://example.com\""
                        + " xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\""
                        + " xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\""
                        + " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
                        + " xmlns:ns0=\"http://xmlsoap.org/Ping\""
                        + " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
                        + "<env:Body wsu:Id=\"body\">"
                        + "<ns0:Ping xsi:type=\"ns0:ping\">"
                        + "<ns0:text xsi:type=\"xsd:string\">hello</ns0:text>"
                        + "</ns0:Ping>"
                        + "</env:Body>"
                        + "</env:Envelope>";

        final String c14nXML =
                "<env:Body"
                        + " xmlns=\"http://example.com\""
                        + " xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\""
                        + " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\""
                        + " wsu:Id=\"body\">"
                        + "<ns0:Ping xmlns:ns0=\"http://xmlsoap.org/Ping\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ns0:ping\">"
                        + "<ns0:text xsi:type=\"xsd:string\">hello</ns0:text>"
                        + "</ns0:Ping>"
                        + "</env:Body>";

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final List<String> inclusiveNamespaces = new ArrayList<>();
        inclusiveNamespaces.add("#default");
        final Canonicalizer20010315_ExclOmitCommentsTransformer c = new Canonicalizer20010315_ExclOmitCommentsTransformer();
        final Map<String, Object> transformerProperties = new HashMap<>();
        transformerProperties.put(Canonicalizer20010315_Excl.INCLUSIVE_NAMESPACES_PREFIX_LIST, inclusiveNamespaces);
        transformerProperties.put(Canonicalizer20010315_Excl.PROPAGATE_DEFAULT_NAMESPACE, Boolean.TRUE);
        c.setProperties(transformerProperties);
        c.setOutputStream(baos);
        canonicalize(c, new StringReader(XML), new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"));

        assertEquals(new String(baos.toByteArray(), java.nio.charset.StandardCharsets.UTF_8), c14nXML);
    }

    @Test
    public void testPropagateDefaultNs3() throws Exception {
        final String XML =
                "<Envelope"
                        + " xmlns=\"http://example.com\""
                        + " xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\""
                        + " xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\""
                        + " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
                        + " xmlns:ns0=\"http://xmlsoap.org/Ping\""
                        + " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
                        + "<env:Body wsu:Id=\"body\">"
                        + "<ns0:Ping xsi:type=\"ns0:ping\">"
                        + "<ns0:text xmlns=\"\" xsi:type=\"xsd:string\">hello</ns0:text>"
                        + "</ns0:Ping>"
                        + "</env:Body>"
                        + "</Envelope>";

        final String c14nXML =
                "<env:Body"
                        + " xmlns=\"http://example.com\""
                        + " xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\""
                        + " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\""
                        + " wsu:Id=\"body\">"
                        + "<ns0:Ping xmlns:ns0=\"http://xmlsoap.org/Ping\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ns0:ping\">"
                        + "<ns0:text xmlns=\"\" xsi:type=\"xsd:string\">hello</ns0:text>"
                        + "</ns0:Ping>"
                        + "</env:Body>";

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final List<String> inclusiveNamespaces = new ArrayList<>();
        inclusiveNamespaces.add("#default");
        final Canonicalizer20010315_ExclOmitCommentsTransformer c = new Canonicalizer20010315_ExclOmitCommentsTransformer();
        final Map<String, Object> transformerProperties = new HashMap<>();
        transformerProperties.put(Canonicalizer20010315_Excl.INCLUSIVE_NAMESPACES_PREFIX_LIST, inclusiveNamespaces);
        transformerProperties.put(Canonicalizer20010315_Excl.PROPAGATE_DEFAULT_NAMESPACE, Boolean.TRUE);
        c.setProperties(transformerProperties);
        c.setOutputStream(baos);
        canonicalize(c, new StringReader(XML), new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"));

        assertEquals(new String(baos.toByteArray(), java.nio.charset.StandardCharsets.UTF_8), c14nXML);
    }

    @Test
    public void testPropagateDefaultNs4() throws Exception {
        final String XML =
                "<Envelope"
                        + " xmlns=\"\""
                        + " xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\""
                        + " xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\""
                        + " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
                        + " xmlns:ns0=\"http://xmlsoap.org/Ping\""
                        + " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
                        + "<env:Body wsu:Id=\"body\">"
                        + "<ns0:Ping xsi:type=\"ns0:ping\">"
                        + "<ns0:text xsi:type=\"xsd:string\">hello</ns0:text>"
                        + "</ns0:Ping>"
                        + "</env:Body>"
                        + "</Envelope>";

        final String c14nXML =
                "<env:Body"
                        + " xmlns=\"\""
                        + " xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\""
                        + " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\""
                        + " wsu:Id=\"body\">"
                        + "<ns0:Ping xmlns:ns0=\"http://xmlsoap.org/Ping\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ns0:ping\">"
                        + "<ns0:text xsi:type=\"xsd:string\">hello</ns0:text>"
                        + "</ns0:Ping>"
                        + "</env:Body>";

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final List<String> inclusiveNamespaces = new ArrayList<>();
        inclusiveNamespaces.add("#default");
        final Canonicalizer20010315_ExclOmitCommentsTransformer c = new Canonicalizer20010315_ExclOmitCommentsTransformer();
        final Map<String, Object> transformerProperties = new HashMap<>();
        transformerProperties.put(Canonicalizer20010315_Excl.INCLUSIVE_NAMESPACES_PREFIX_LIST, inclusiveNamespaces);
        transformerProperties.put(Canonicalizer20010315_Excl.PROPAGATE_DEFAULT_NAMESPACE, Boolean.TRUE);
        c.setProperties(transformerProperties);
        c.setOutputStream(baos);
        canonicalize(c, new StringReader(XML), new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body"));

        assertEquals(new String(baos.toByteArray(), java.nio.charset.StandardCharsets.UTF_8), c14nXML);
    }

    @Test
    public void testPropagateDefaultNs5() throws Exception {
        final String XML =
                "<env:Envelope"
                        + " xmlns=\"http://example.com\""
                        + " xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\""
                        + " xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\""
                        + " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
                        + " xmlns:ns0=\"http://xmlsoap.org/Ping\""
                        + " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
                        + "<env:Body xmlns=\"\" wsu:Id=\"body\">"
                        + "<ns0:Ping xsi:type=\"ns0:ping\">"
                        + "<ns0:text xsi:type=\"xsd:string\">hello</ns0:text>"
                        + "</ns0:Ping>"
                        + "</env:Body>"
                        + "</env:Envelope>";

        final String c14nXML =
                "<ns0:Ping xmlns=\"\" xmlns:ns0=\"http://xmlsoap.org/Ping\" " +
                        "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ns0:ping\">"
                        + "<ns0:text xsi:type=\"xsd:string\">hello</ns0:text>"
                        + "</ns0:Ping>";

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final List<String> inclusiveNamespaces = new ArrayList<>();
        inclusiveNamespaces.add("#default");
        final Canonicalizer20010315_ExclOmitCommentsTransformer c = new Canonicalizer20010315_ExclOmitCommentsTransformer();
        final Map<String, Object> transformerProperties = new HashMap<>();
        transformerProperties.put(Canonicalizer20010315_Excl.INCLUSIVE_NAMESPACES_PREFIX_LIST, inclusiveNamespaces);
        transformerProperties.put(Canonicalizer20010315_Excl.PROPAGATE_DEFAULT_NAMESPACE, Boolean.TRUE);
        c.setProperties(transformerProperties);
        c.setOutputStream(baos);
        canonicalize(c, new StringReader(XML), new QName("http://xmlsoap.org/Ping", "Ping"));

        assertEquals(new String(baos.toByteArray(), java.nio.charset.StandardCharsets.UTF_8), c14nXML);
    }

    private void canonicalize(
            Canonicalizer20010315_Excl c, InputStream inputStream, QName elementName)
            throws XMLStreamException {
        canonicalize(c, xmlInputFactory.createXMLEventReader(inputStream), elementName);
    }

    private void canonicalize(
            Canonicalizer20010315_Excl c, Reader reader, QName elementName)
            throws XMLStreamException {
        canonicalize(c, xmlInputFactory.createXMLEventReader(reader), elementName);
    }

    private void canonicalize(
            Canonicalizer20010315_Excl c, XMLEventReader xmlEventReader, QName elementName)
            throws XMLStreamException {

        XMLSecEvent xmlSecEvent = null;
        while (xmlEventReader.hasNext()) {
            xmlSecEvent = (XMLSecEvent) xmlEventReader.nextEvent();
            if (xmlSecEvent.isStartElement() && xmlSecEvent.asStartElement().getName().equals(elementName)) {
                break;
            }
        }

        while (xmlEventReader.hasNext()) {
            c.transform(xmlSecEvent);
            if (xmlSecEvent.isEndElement() && xmlSecEvent.asEndElement().getName().equals(elementName)) {
                break;
            }
            xmlSecEvent = (XMLSecEvent) xmlEventReader.nextEvent();
        }
    }

    public static byte[] getBytesFromResource(URL resource) throws IOException {

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final InputStream inputStream = resource.openStream();
        try {
            final byte[] buf = new byte[1024];
            int len;
            while ((len = inputStream.read(buf)) > 0) {
                baos.write(buf, 0, len);
            }

            return baos.toByteArray();
        } finally {
            inputStream.close();
        }
    }
}