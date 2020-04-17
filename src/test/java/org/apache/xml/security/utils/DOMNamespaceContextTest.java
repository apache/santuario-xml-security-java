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
package org.apache.xml.security.utils;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.traversal.DocumentTraversal;
import org.w3c.dom.traversal.TreeWalker;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.StringReader;

import static javax.xml.XMLConstants.DEFAULT_NS_PREFIX;
import static javax.xml.XMLConstants.NULL_NS_URI;
import static javax.xml.XMLConstants.XMLNS_ATTRIBUTE;
import static javax.xml.XMLConstants.XMLNS_ATTRIBUTE_NS_URI;
import static javax.xml.XMLConstants.XML_NS_PREFIX;
import static javax.xml.XMLConstants.XML_NS_URI;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.w3c.dom.traversal.NodeFilter.SHOW_ELEMENT;

public class DOMNamespaceContextTest {

    private static final DocumentBuilderFactory DEFAULT_DOCUMENT_BUILDER_FACTORY;

    static {
        DEFAULT_DOCUMENT_BUILDER_FACTORY = DocumentBuilderFactory.newInstance();
        DEFAULT_DOCUMENT_BUILDER_FACTORY.setNamespaceAware(true);
    }

    private static Document createDocument(String xml) throws IOException, SAXException, ParserConfigurationException {
        return DEFAULT_DOCUMENT_BUILDER_FACTORY.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
    }

    @Test
    public void testUnboundDefaultNamespace() throws Exception {
        Document document = createDocument("<root/>");
        DOMNamespaceContext namespaceContext = new DOMNamespaceContext(document);
        assertThrows(IllegalArgumentException.class, () -> namespaceContext.getNamespaceURI(null));
        assertThat(namespaceContext.getNamespaceURI(DEFAULT_NS_PREFIX), is(equalTo(NULL_NS_URI)));
        assertThat(namespaceContext.getNamespaceURI(XML_NS_PREFIX), is(equalTo(XML_NS_URI)));
        assertThat(namespaceContext.getNamespaceURI(XMLNS_ATTRIBUTE), is(equalTo(XMLNS_ATTRIBUTE_NS_URI)));
        assertThat(namespaceContext.getNamespaceURI("unbound-ns"), is(equalTo(NULL_NS_URI)));
        assertThrows(IllegalArgumentException.class, () -> namespaceContext.getPrefix(null));
        assertThat(namespaceContext.getPrefix(NULL_NS_URI), is(equalTo(DEFAULT_NS_PREFIX)));
        assertThat(namespaceContext.getPrefix(XML_NS_URI), is(equalTo(XML_NS_PREFIX)));
        assertThat(namespaceContext.getPrefix(XMLNS_ATTRIBUTE_NS_URI), is(equalTo(XMLNS_ATTRIBUTE)));
        assertThat(namespaceContext.getPrefix("urn:unbound-ns"), is(nullValue()));
    }

    @Test
    public void testBoundDefaultNamespace() throws Exception {
        Document document = createDocument("<root xmlns='urn:ns'/>");
        TreeWalker walker = ((DocumentTraversal) document).createTreeWalker(document, SHOW_ELEMENT, null, true);
        Node root = walker.nextNode();
        DOMNamespaceContext namespaceContext = new DOMNamespaceContext(root);
        assertThrows(IllegalArgumentException.class, () -> namespaceContext.getNamespaceURI(null));
        assertThat(namespaceContext.getNamespaceURI(DEFAULT_NS_PREFIX), is(equalTo("urn:ns")));
        assertThat(namespaceContext.getNamespaceURI(XML_NS_PREFIX), is(equalTo(XML_NS_URI)));
        assertThat(namespaceContext.getNamespaceURI(XMLNS_ATTRIBUTE), is(equalTo(XMLNS_ATTRIBUTE_NS_URI)));
        assertThat(namespaceContext.getNamespaceURI("unbound-ns"), is(equalTo(NULL_NS_URI)));
        assertThrows(IllegalArgumentException.class, () -> namespaceContext.getPrefix(null));
        assertThat(namespaceContext.getPrefix(NULL_NS_URI), is(nullValue()));
        assertThat(namespaceContext.getPrefix("urn:ns"), is(equalTo(DEFAULT_NS_PREFIX)));
        assertThat(namespaceContext.getPrefix(XML_NS_URI), is(equalTo(XML_NS_PREFIX)));
        assertThat(namespaceContext.getPrefix(XMLNS_ATTRIBUTE_NS_URI), is(equalTo(XMLNS_ATTRIBUTE)));
        assertThat(namespaceContext.getPrefix("urn:unbound-ns"), is(nullValue()));
    }

    @Test
    public void testNamespaceInheritance() throws Exception {
        Document document = createDocument("<root xmlns='urn:ns'><branch xmlns:ns1='urn:ns1'/></root>");
        TreeWalker walker = ((DocumentTraversal) document).createTreeWalker(document, SHOW_ELEMENT, null, true);
        Node root = walker.nextNode();
        DOMNamespaceContext namespaceContext = new DOMNamespaceContext(root);
        assertThat(namespaceContext.getNamespaceURI(DEFAULT_NS_PREFIX), is(equalTo("urn:ns")));
        assertThat(namespaceContext.getPrefix("urn:ns"), is(equalTo(DEFAULT_NS_PREFIX)));
        assertThat(namespaceContext.getNamespaceURI("urn:ns1"), is(equalTo(DEFAULT_NS_PREFIX)));
        assertThat(namespaceContext.getPrefix("ns1"), is(nullValue()));
        Node branch = walker.nextNode();
        namespaceContext.setContext(branch);
        assertThat(namespaceContext.getNamespaceURI(DEFAULT_NS_PREFIX), is(equalTo("urn:ns")));
        assertThat(namespaceContext.getPrefix("urn:ns"), is(equalTo(DEFAULT_NS_PREFIX)));
        assertThat(namespaceContext.getNamespaceURI("ns1"), is(equalTo("urn:ns1")));
        assertThat(namespaceContext.getPrefix("urn:ns1"), is(equalTo("ns1")));
    }

    @Test
    public void testOverriddenDefaultNamespace() throws Exception {
        Document document = createDocument("<root xmlns='urn:ns1'><branch xmlns='urn:ns2'/></root>");
        TreeWalker walker = ((DocumentTraversal) document).createTreeWalker(document, SHOW_ELEMENT, null, true);
        Node root = walker.nextNode();
        DOMNamespaceContext namespaceContext = new DOMNamespaceContext(root);
        assertThat(namespaceContext.getNamespaceURI(DEFAULT_NS_PREFIX), is(equalTo("urn:ns1")));
        assertThat(namespaceContext.getPrefix("urn:ns1"), is(equalTo(DEFAULT_NS_PREFIX)));
        assertThat(namespaceContext.getPrefix("urn:ns2"), is(nullValue()));
        Node branch = walker.nextNode();
        namespaceContext.setContext(branch);
        assertThat(namespaceContext.getNamespaceURI(DEFAULT_NS_PREFIX), is(equalTo("urn:ns2")));
        assertThat(namespaceContext.getPrefix("urn:ns2"), is(equalTo(DEFAULT_NS_PREFIX)));
        assertThat(namespaceContext.getPrefix("urn:ns1"), is(nullValue()));
    }

    @Test
    public void testGetPrefixesIsUnsupported() throws Exception {
        Document document = createDocument("<root/>");
        TreeWalker walker = ((DocumentTraversal) document).createTreeWalker(document, SHOW_ELEMENT, null, true);
        Node root = walker.nextNode();
        DOMNamespaceContext namespaceContext = new DOMNamespaceContext(root);
        assertThrows(UnsupportedOperationException.class, () -> namespaceContext.getPrefixes(NULL_NS_URI));
    }
}
