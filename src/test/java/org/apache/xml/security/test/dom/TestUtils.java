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
package org.apache.xml.security.test.dom;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.security.parser.XMLParserException;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class TestUtils {

    private static final DocumentBuilderFactory DBF = DocumentBuilderFactory.newInstance();
    private static final boolean isJava11Compatible;
    // The class-path to test resources
    private static final String RESOURCE_PATH = "/org/apache/xml/security/test/javax/xml/crypto/dsig/";

    static {
        DBF.setNamespaceAware(true);
        try {
            DBF.setFeature(javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING, true);
        } catch (ParserConfigurationException e) {
            // Ignore: DocumentBuilderFactory is required to support the secure processing feature
            e.printStackTrace();        // NOPMD
        }

        String version = System.getProperty("java.version");
        if (version.indexOf('.') > 0) {
            version = version.substring(0, version.indexOf('.'));
        }
        if (version.indexOf('-') > 0) {
            version = version.substring(0, version.indexOf('-'));
        }

        isJava11Compatible = Integer.valueOf(version) >= 11;
    }

    /**
     * Method createDSctx
     *
     * @param doc
     * @param prefix
     * @param namespace
     * @return the element.
     */
    public static Element createDSctx(Document doc, String prefix, String namespace) {
        if (prefix == null || prefix.trim().length() == 0) {
            throw new IllegalArgumentException("You must supply a prefix");
        }

        Element ctx = doc.createElementNS(null, "namespaceContext");
        ctx.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:" + prefix.trim(), namespace);
        return ctx;
    }

    public static Document newDocument() throws ParserConfigurationException {
        return DBF.newDocumentBuilder().newDocument();
    }

    /**
     * Create a test method to read input XML Fragment bytes and return a Document with root element "ROOT".
     * The XML fragment are wrapped in a "ROOT" element to make it a valid XML document.
     *
     * @param xmlFragment the XML fragment bytes
     *                    (e.g. "<a>text 2</a><a><b>text 2</b></a>".getBytes())
     * @return the Document with root element "ROOT"
     */
    public static Document xmlFragmentToDocument(byte[] xmlFragment) throws XMLParserException, IOException {
        if (xmlFragment == null || xmlFragment.length == 0) {
            throw new IllegalArgumentException("XML fragment cannot be null or empty");
        }

        String xml = new String(xmlFragment, StandardCharsets.UTF_8);
        String xmlDocument = "<ROOT>" + xml + "</ROOT>";

        try (ByteArrayInputStream is = new ByteArrayInputStream(xmlDocument.getBytes(StandardCharsets.UTF_8))) {
            return XMLUtils.read(is, true);
        }
    }

    /**
     * Get a test document from a classpath resource.
     * @param fileName the file name of the resource
     * @return the Document
     * @throws XMLParserException if an error occurs while parsing the XML document
     */
    public static Document getTestDocumentFromResource(String fileName) throws XMLParserException {
        // read document from classpath resource
        return XMLUtils.read(TestUtils.class
                .getResourceAsStream(RESOURCE_PATH + fileName), true);
    }

    public static boolean isJava11Compatible() {
        return isJava11Compatible;
    }
}
