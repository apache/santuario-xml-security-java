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
package org.apache.xml.security.test.stax.config;

import java.net.URL;

import javax.xml.XMLConstants;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.sax.SAXTransformerFactory;
import javax.xml.transform.sax.TransformerHandler;

import org.apache.xml.security.stax.config.XIncludeHandler;
import org.apache.xml.security.utils.ClassLoaderUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests that documents pulled in via xi:include are parsed with the same hardening
 * as the top-level configuration document.
 */
class XIncludeHandlerTest {

    private static final String BASE = "org/apache/xml/security/test/stax/config/";

    @Test
    void testIncludeResolved() throws Exception {
        Document document = parse(BASE + "xinclude-outer.xml");
        assertEquals("inner",
            document.getDocumentElement().getElementsByTagName("inner").item(0).getNodeName());
    }

    @Test
    void testDoctypeInIncludedDocumentRejected() throws Exception {
        SAXException ex = assertThrows(SAXException.class, () -> parse(BASE + "xinclude-outer-doctype.xml"));
        assertNotNull(ex);
    }

    private static Document parse(String resource) throws Exception {
        URL url = ClassLoaderUtils.getResource(resource, XIncludeHandlerTest.class);
        assertNotNull(url);

        SAXTransformerFactory transformerFactory = (SAXTransformerFactory) TransformerFactory.newInstance();
        transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, Boolean.TRUE);
        TransformerHandler transformerHandler = transformerFactory.newTransformerHandler();
        DOMResult domResult = new DOMResult();
        transformerHandler.setResult(domResult);

        SAXParserFactory saxParserFactory = SAXParserFactory.newInstance();
        saxParserFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, Boolean.TRUE);
        saxParserFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        saxParserFactory.setXIncludeAware(false);
        saxParserFactory.setNamespaceAware(true);
        SAXParser saxParser = saxParserFactory.newSAXParser();
        saxParser.parse(url.toExternalForm(), new XIncludeHandler(transformerHandler));
        return (Document) domResult.getNode();
    }
}
