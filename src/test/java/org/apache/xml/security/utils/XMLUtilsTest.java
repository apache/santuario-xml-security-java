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

import java.io.StringReader;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

import static javax.xml.XMLConstants.DEFAULT_NS_PREFIX;
import static javax.xml.XMLConstants.NULL_NS_URI;
import static org.apache.xml.security.test.stax.utils.TestUtils.convertNodeToQName;
import static org.apache.xml.security.utils.XMLUtils.convertQNameToElement;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.w3c.dom.Node.ELEMENT_NODE;

public class XMLUtilsTest {

    @Test
    public void testConvertQNameToElement() throws Throwable {
        DocumentBuilder documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document document = documentBuilder.newDocument();
        Element element = convertQNameToElement(document, new QName(NULL_NS_URI, "LocalPart", DEFAULT_NS_PREFIX));
        assertThat(element.getNodeType(), is(ELEMENT_NODE));
        assertThat(element.getTagName(), is(equalTo("LocalPart")));
        assertThat(element.getNamespaceURI(), is(nullValue()));
        assertThat(element.getPrefix(), is(nullValue()));
    }

    @Test
    public void testConvertQNameToElementWithNamespace() throws Throwable {
        DocumentBuilder documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document document = documentBuilder.newDocument();
        Element element = convertQNameToElement(document, new QName("urn:abc:def", "LocalPart", DEFAULT_NS_PREFIX));
        assertThat(element.getNodeType(), is(ELEMENT_NODE));
        assertThat(element.getLocalName(), is(equalTo("LocalPart")));
        assertThat(element.getTagName(), is(equalTo("LocalPart")));
        assertThat(element.getNamespaceURI(), is(equalTo("urn:abc:def")));
        assertThat(element.getPrefix(), is(nullValue()));
    }

    @Test
    public void testConvertQNameToElementWithPrefix() throws Throwable {
        DocumentBuilder documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document document = documentBuilder.newDocument();
        Element element = convertQNameToElement(document, new QName("urn:abc:def", "LocalPart", "abc"));
        assertThat(element.getNodeType(), is(ELEMENT_NODE));
        assertThat(element.getLocalName(), is(equalTo("LocalPart")));
        assertThat(element.getTagName(), is(equalTo("abc:LocalPart")));
        assertThat(element.getNamespaceURI(), is("urn:abc:def"));
        assertThat(element.getPrefix(), is(equalTo("abc")));
    }

    @Test
    public void testConvertNodeToQName() throws Throwable {
        String xml = "<nodeName/>";
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        Document document = documentBuilderFactory.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
        Node node = document.getFirstChild();
        QName name = convertNodeToQName(node);
        assertThat(name.getLocalPart(), is(equalTo("nodeName")));
        assertThat(name.getNamespaceURI(), is(NULL_NS_URI));
        assertThat(name.getPrefix(), is(DEFAULT_NS_PREFIX));
    }

    @Test
    public void testConvertNodeToQNameThrowsWhenDomLevel1() throws Throwable {
        String xml = "<prefix:localPart/>";
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(false);
        Document document = documentBuilderFactory.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
        Node node = document.getFirstChild();
        assertThrows(IllegalArgumentException.class, () ->{
            convertNodeToQName(node);
        });
    }

    @Test
    public void testConvertNodeToQNameThrowsWhenPrefixNotBound() throws Throwable {
        String xml = "<prefix:localPart/>";
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(false);
        Document document = documentBuilderFactory.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
        Node node = document.getFirstChild();
        assertThrows(IllegalArgumentException.class, () ->{
            convertNodeToQName(node);
        });
    }

    @Test
    public void testConvertNodeToQNameWithPrefix() throws Throwable {
        String xml = "<prefix:localPart xmlns:prefix='urn:test:ns'/>";
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        Document document = documentBuilderFactory.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
        Node node = document.getFirstChild();
        QName name = convertNodeToQName(node);
        assertThat(name.getLocalPart(), is(equalTo("localPart")));
        assertThat(name.getNamespaceURI(), is(equalTo("urn:test:ns")));
        assertThat(name.getPrefix(), is(equalTo("prefix")));
    }

    @Test
    public void testConvertNodeToQNameWithDefaultNamespace() throws Throwable {
        String xml = "<localPart xmlns='urn:test:ns'/>";
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        Document document = documentBuilderFactory.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
        Node node = document.getFirstChild();
        QName name = convertNodeToQName(node);
        assertThat(name.getLocalPart(), is(equalTo("localPart")));
        assertThat(name.getNamespaceURI(), is(equalTo("urn:test:ns")));
        assertThat(name.getPrefix(), is(DEFAULT_NS_PREFIX));
    }
}