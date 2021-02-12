/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.xml.security.stax.ext;

import java.io.IOException;
import java.io.StringReader;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamException;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.OutboundSecurityContextImpl;
import org.apache.xml.security.stax.impl.OutputProcessorChainImpl;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.traversal.DocumentTraversal;
import org.w3c.dom.traversal.TreeWalker;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import static org.apache.xml.security.test.stax.utils.TestUtils.convertNodeToStartElement;
import static org.apache.xml.security.test.stax.utils.TestUtils.convertStartToEndElement;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.w3c.dom.traversal.NodeFilter.SHOW_ELEMENT;

public class XPathElementSelectorTest {

    private static final DocumentBuilderFactory DEFAULT_DOCUMENT_BUILDER_FACTORY;

    static {
        DEFAULT_DOCUMENT_BUILDER_FACTORY = DocumentBuilderFactory.newInstance();
        DEFAULT_DOCUMENT_BUILDER_FACTORY.setNamespaceAware(true);
    }

    private static Document createDocument(String xml) throws IOException, SAXException, ParserConfigurationException {
        return DEFAULT_DOCUMENT_BUILDER_FACTORY.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
    }

    private static TreeWalker createTreeWalker(Document document) {
        return ((DocumentTraversal) document).createTreeWalker(document, SHOW_ELEMENT, null, true);
    }

    @Test
    public void testOutputProcessorIsInstalledUponInitialization() {
        OutputProcessorChain outputProcessorChain = new OutputProcessorChainImpl(new OutboundSecurityContextImpl(new XMLSecurityProperties()));
        assertThat(outputProcessorChain.getProcessors(), is(empty()));
        XPathElementSelector elementSelector = new XPathElementSelector("//*", XPathModifier.Path);
        elementSelector.init(outputProcessorChain);
        assertThat(outputProcessorChain.getProcessors(), hasSize(1));
        assertThat(outputProcessorChain.getProcessors().get(0), is(instanceOf(XPathOutputProcessor.class)));
    }

    @Test
    public void testSelectNullDoesNotMatch() {
        OutputProcessorChain outputProcessorChain = new OutputProcessorChainImpl(new OutboundSecurityContextImpl(new XMLSecurityProperties()));
        XPathElementSelector elementSelector = new XPathElementSelector("//*", XPathModifier.Path);
        elementSelector.init(outputProcessorChain);
        assertThat(elementSelector.select(null, outputProcessorChain), is(false));
    }

    @Test
    public void testSelectAbsolutePath() throws Exception {
        OutputProcessorChain outputProcessorChain = new OutputProcessorChainImpl(new OutboundSecurityContextImpl(new XMLSecurityProperties()));
        Document document = createDocument("<root><branch/></root>");
        String expression = "/root/branch";
        XPathElementSelector elementSelector = new XPathElementSelector(expression, XPathModifier.Path);
        elementSelector.init(outputProcessorChain);
        TreeWalker treeWalker = createTreeWalker(document);

        XMLSecStartElement root = convertNodeToStartElement(treeWalker.nextNode());
        processEvent(outputProcessorChain, root);
        assertThat(elementSelector.select(root, outputProcessorChain), is(false));

        XMLSecStartElement branch = convertNodeToStartElement(treeWalker.nextNode());
        processEvent(outputProcessorChain, branch);
        assertThat(elementSelector.select(branch, outputProcessorChain), is(true));
        processEvent(outputProcessorChain, convertStartToEndElement(branch));
        assertThat(outputProcessorChain.getSecurityContext().get(Element.class), is(notNullValue()));
        processEvent(outputProcessorChain, convertStartToEndElement(root));
        assertThat(outputProcessorChain.getSecurityContext().get(Element.class), is(nullValue()));
    }

    private static void processEvent(OutputProcessorChain outputProcessorChain, XMLSecEvent event) throws XMLSecurityException, XMLStreamException {
        outputProcessorChain.reset();
        outputProcessorChain.processEvent(event);
    }

    @Test
    public void testSelectPathMatchesMultipleElements() throws Exception {
        OutputProcessorChain outputProcessorChain = new OutputProcessorChainImpl(new OutboundSecurityContextImpl(new XMLSecurityProperties()));
        Document document = createDocument("<root><twig number='1'/><branch><twig number='2'><leaf/></twig></branch></root>");
        String expression = "//twig";
        XPathElementSelector elementSelector = new XPathElementSelector(expression, XPathModifier.Path);
        elementSelector.init(outputProcessorChain);
        TreeWalker treeWalker = createTreeWalker(document);

        XMLSecStartElement root = convertNodeToStartElement(treeWalker.nextNode());
        processEvent(outputProcessorChain, root);
        assertThat(elementSelector.select(root, outputProcessorChain), is(false));

        XMLSecStartElement twig1 = convertNodeToStartElement(treeWalker.nextNode());
        processEvent(outputProcessorChain, twig1);
        assertThat(elementSelector.select(twig1, outputProcessorChain), is(true));

        processEvent(outputProcessorChain, convertStartToEndElement(twig1));

        XMLSecStartElement branch = convertNodeToStartElement(treeWalker.nextNode());
        processEvent(outputProcessorChain, branch);
        assertThat(elementSelector.select(branch, outputProcessorChain), is(false));

        XMLSecStartElement twig2 = convertNodeToStartElement(treeWalker.nextNode());
        processEvent(outputProcessorChain, twig2);
        assertThat(elementSelector.select(twig2, outputProcessorChain), is(true));

        XMLSecStartElement leaf = convertNodeToStartElement(treeWalker.nextNode());
        processEvent(outputProcessorChain, leaf);
        assertThat(elementSelector.select(leaf, outputProcessorChain), is(false));
        processEvent(outputProcessorChain, convertStartToEndElement(leaf));
        processEvent(outputProcessorChain, convertStartToEndElement(twig2));
        processEvent(outputProcessorChain, convertStartToEndElement(branch));
        processEvent(outputProcessorChain, convertStartToEndElement(twig1));
    }

    @Test
    public void testSelectPathMatchesAttributes() throws Exception {
        OutputProcessorChain outputProcessorChain = new OutputProcessorChainImpl(new OutboundSecurityContextImpl(new XMLSecurityProperties()));
        Document document = createDocument("<root><branch1 attr1='foo'/><branch2 attr2='foo'/><branch3 attr1='foo'/></root>");
        String expression = "//*[@attr1='foo']";
        XPathElementSelector elementSelector = new XPathElementSelector(expression, XPathModifier.Path);
        elementSelector.init(outputProcessorChain);
        TreeWalker treeWalker = createTreeWalker(document);

        XMLSecStartElement root = convertNodeToStartElement(treeWalker.nextNode());
        processEvent(outputProcessorChain, root);
        assertThat(elementSelector.select(root, outputProcessorChain), is(false));

        XMLSecStartElement branch1 = convertNodeToStartElement(treeWalker.nextNode());
        processEvent(outputProcessorChain, branch1);
        assertThat(elementSelector.select(branch1, outputProcessorChain), is(true));
        processEvent(outputProcessorChain, convertStartToEndElement(branch1));

        XMLSecStartElement branch2 = convertNodeToStartElement(treeWalker.nextNode());
        processEvent(outputProcessorChain, branch2);
        assertThat(elementSelector.select(branch2, outputProcessorChain), is(false));
        processEvent(outputProcessorChain, convertStartToEndElement(branch2));

        XMLSecStartElement branch3 = convertNodeToStartElement(treeWalker.nextNode());
        processEvent(outputProcessorChain, branch3);
        assertThat(elementSelector.select(branch3, outputProcessorChain), is(true));
        processEvent(outputProcessorChain, convertStartToEndElement(branch3));
        processEvent(outputProcessorChain, convertStartToEndElement(root));
    }

    @Test
    public void testSelectPathMatchesPrefix() throws Exception {
        OutputProcessorChain outputProcessorChain = new OutputProcessorChainImpl(new OutboundSecurityContextImpl(new XMLSecurityProperties()));
        Document document = createDocument("<root><branch><ns0:leaf xmlns:ns0='urn:ns0'/></branch><ns0:leaf xmlns:ns0='urn:ns1'/></root>");
        String expression = "//ns0:leaf";
        XPathElementSelector elementSelector = new XPathElementSelector(expression, XPathModifier.Path);
        elementSelector.init(outputProcessorChain);
        TreeWalker treeWalker = createTreeWalker(document);

        XMLSecStartElement root = convertNodeToStartElement(treeWalker.nextNode());
        processEvent(outputProcessorChain, root);
        assertThat(elementSelector.select(root, outputProcessorChain), is(false));

        XMLSecStartElement branch = convertNodeToStartElement(treeWalker.nextNode());
        processEvent(outputProcessorChain, branch);
        assertThat(elementSelector.select(branch, outputProcessorChain), is(false));

        XMLSecStartElement leaf1 = convertNodeToStartElement(treeWalker.nextNode());
        processEvent(outputProcessorChain, leaf1);
        assertThat(elementSelector.select(leaf1, outputProcessorChain), is(true));
        processEvent(outputProcessorChain, convertStartToEndElement(leaf1));
        processEvent(outputProcessorChain, convertStartToEndElement(branch));

        XMLSecStartElement leaf2 = convertNodeToStartElement(treeWalker.nextNode());
        processEvent(outputProcessorChain, leaf2);
        assertThat(elementSelector.select(leaf2, outputProcessorChain), is(true));
        processEvent(outputProcessorChain, convertStartToEndElement(leaf2));
        processEvent(outputProcessorChain, convertStartToEndElement(root));
    }

    @Test
    public void testSelectPathMatchesLocalName() throws Exception {
        OutputProcessorChain outputProcessorChain = new OutputProcessorChainImpl(new OutboundSecurityContextImpl(new XMLSecurityProperties()));
        Document document = createDocument("<root><branch><ns0:leaf xmlns:ns0='urn:ns0'/></branch><ns1:leaf xmlns:ns1='urn:ns1'/></root>");
        String expression = "//*[local-name() = 'leaf']";
        XPathElementSelector elementSelector = new XPathElementSelector(expression, XPathModifier.Path);
        elementSelector.init(outputProcessorChain);
        TreeWalker treeWalker = createTreeWalker(document);

        XMLSecStartElement root = convertNodeToStartElement(treeWalker.nextNode());
        processEvent(outputProcessorChain, root);
        assertThat(elementSelector.select(root, outputProcessorChain), is(false));

        XMLSecStartElement branch = convertNodeToStartElement(treeWalker.nextNode());
        processEvent(outputProcessorChain, branch);
        assertThat(elementSelector.select(branch, outputProcessorChain), is(false));

        XMLSecStartElement leaf1 = convertNodeToStartElement(treeWalker.nextNode());
        processEvent(outputProcessorChain, leaf1);
        assertThat(elementSelector.select(leaf1, outputProcessorChain), is(true));
        processEvent(outputProcessorChain, convertStartToEndElement(leaf1));
        processEvent(outputProcessorChain, convertStartToEndElement(branch));

        XMLSecStartElement leaf2 = convertNodeToStartElement(treeWalker.nextNode());
        processEvent(outputProcessorChain, leaf2);
        assertThat(elementSelector.select(leaf2, outputProcessorChain), is(true));
        processEvent(outputProcessorChain, convertStartToEndElement(leaf2));
        processEvent(outputProcessorChain, convertStartToEndElement(root));
    }

    @Test
    public void testSelectLocalNameAndNamespaceUri() throws Exception {
        OutputProcessorChain outputProcessorChain = new OutputProcessorChainImpl(new OutboundSecurityContextImpl(new XMLSecurityProperties()));
        Document document = createDocument("<root><branch><ns0:leaf xmlns:ns0='urn:ns0'/></branch><ns1:leaf xmlns:ns1='urn:ns1'/><ns2:leaf xmlns:ns2='urn:ns0'/></root>");
        String expression = "//*[namespace-uri() = 'urn:ns0' and local-name() = 'leaf']";
        XPathElementSelector elementSelector = new XPathElementSelector(expression, XPathModifier.Path);
        elementSelector.init(outputProcessorChain);
        TreeWalker treeWalker = createTreeWalker(document);

        XMLSecStartElement root = convertNodeToStartElement(treeWalker.nextNode());
        processEvent(outputProcessorChain, root);
        assertThat(elementSelector.select(root, outputProcessorChain), is(false));

        XMLSecStartElement branch = convertNodeToStartElement(treeWalker.nextNode());
        processEvent(outputProcessorChain, branch);
        assertThat(elementSelector.select(branch, outputProcessorChain), is(false));

        XMLSecStartElement leaf1 = convertNodeToStartElement(treeWalker.nextNode());
        processEvent(outputProcessorChain, leaf1);
        assertThat(elementSelector.select(leaf1, outputProcessorChain), is(true));
        processEvent(outputProcessorChain, convertStartToEndElement(leaf1));
        processEvent(outputProcessorChain, convertStartToEndElement(branch));

        XMLSecStartElement leaf2 = convertNodeToStartElement(treeWalker.nextNode());
        processEvent(outputProcessorChain, leaf2);
        assertThat(elementSelector.select(leaf2, outputProcessorChain), is(false));
        processEvent(outputProcessorChain, convertStartToEndElement(leaf2));

        XMLSecStartElement leaf3 = convertNodeToStartElement(treeWalker.nextNode());
        processEvent(outputProcessorChain, leaf3);
        assertThat(elementSelector.select(leaf3, outputProcessorChain), is(true));
        processEvent(outputProcessorChain, convertStartToEndElement(leaf3));
        processEvent(outputProcessorChain, convertStartToEndElement(root));
    }

    @Test
    public void testConstructorThrowsWhenRequiredParameterIsNull() {
        assertThrows(NullPointerException.class, () -> new XPathElementSelector(null, "//*", XPathModifier.Path));
        assertThrows(NullPointerException.class, () -> new XPathElementSelector(null, XPathModifier.Path));
        assertThrows(NullPointerException.class, () -> new XPathElementSelector("//*", null));
    }

    @Test
    public void testSelectAttributesDoesNothing() throws Exception {
        OutputProcessorChain outputProcessorChain = new OutputProcessorChainImpl(new OutboundSecurityContextImpl(new XMLSecurityProperties()));
        Document document = createDocument("<root attr='a'/>");
        String expression = "//@attr";
        XPathElementSelector elementSelector = new XPathElementSelector(expression, XPathModifier.Path);
        elementSelector.init(outputProcessorChain);
        TreeWalker treeWalker = createTreeWalker(document);

        XMLSecStartElement root = convertNodeToStartElement(treeWalker.nextNode());
        processEvent(outputProcessorChain, root);
        assertThat(elementSelector.select(root, outputProcessorChain), is(false));
        processEvent(outputProcessorChain, convertStartToEndElement(root));
    }

    @Test
    public void testToString() {
        String expression = "//twig";
        XPathElementSelector elementSelector = new XPathElementSelector(expression, XPathModifier.Path);
        assertThat(elementSelector.toString(), is(equalTo(expression)));
    }

    @Test
    public void testCustomXPathFactory() throws Exception {
        OutputProcessorChain outputProcessorChain = new OutputProcessorChainImpl(new OutboundSecurityContextImpl(new XMLSecurityProperties()));
        Document document = createDocument("<root/>");
        String expression = "/root/branch";
        XPathFactory xPathFactory = spy(XPathFactory.newInstance());
        XPathElementSelector elementSelector = new XPathElementSelector(xPathFactory, expression, XPathModifier.Path);
        elementSelector.init(outputProcessorChain);
        TreeWalker treeWalker = createTreeWalker(document);

        XMLSecStartElement root = convertNodeToStartElement(treeWalker.nextNode());
        processEvent(outputProcessorChain, root);
        elementSelector.select(root, outputProcessorChain);
        verify(xPathFactory).newXPath();
    }

    @Test
    public void testSelectorCanBeUsedWithMultipleDocuments() throws Exception {
        OutputProcessorChain outputProcessorChain1 = new OutputProcessorChainImpl(new OutboundSecurityContextImpl(new XMLSecurityProperties()));
        OutputProcessorChain outputProcessorChain2 = new OutputProcessorChainImpl(new OutboundSecurityContextImpl(new XMLSecurityProperties()));
        Document document1 = createDocument("<root1/>");
        Document document2 = createDocument("<root2/>");
        String expression = "/root2";
        XPathElementSelector elementSelector = new XPathElementSelector(expression, XPathModifier.Path);
        elementSelector.init(outputProcessorChain1);
        TreeWalker treeWalker1 = createTreeWalker(document1);

        XMLSecStartElement root1 = convertNodeToStartElement(treeWalker1.nextNode());
        processEvent(outputProcessorChain1, root1);
        assertThat(elementSelector.select(root1, outputProcessorChain1), is(false));
        elementSelector.init(outputProcessorChain2);
        processEvent(outputProcessorChain1, convertStartToEndElement(root1));
        TreeWalker treeWalker2 = createTreeWalker(document2);

        XMLSecStartElement root2 = convertNodeToStartElement(treeWalker2.nextNode());
        processEvent(outputProcessorChain2, root2);
        assertThat(elementSelector.select(root2, outputProcessorChain2), is(true));
        processEvent(outputProcessorChain2, convertStartToEndElement(root2));
    }

    /**
     * An expression with an undefined prefix will make XPath.compile(expression) fail with an XPathExpressionException.
     * This test tests that such exceptions are ignored and result in "no match".
     * In addition, it tests that such an exception does not break the internal state of the selector, and that it can
     * successfully be used to select another element afterwards.
     */
    @Test
    public void testSelectIgnoresUndefinedPrefix() throws Exception {
        OutputProcessorChain outputProcessorChain1 = new OutputProcessorChainImpl(new OutboundSecurityContextImpl(new XMLSecurityProperties()));
        OutputProcessorChain outputProcessorChain2 = new OutputProcessorChainImpl(new OutboundSecurityContextImpl(new XMLSecurityProperties()));
        Document document1 = createDocument("<root/>");
        Document document2 = createDocument("<ns0:root xmlns:ns0='urn:ns0'/>");
        String expression = "/ns0:root";
        XPathElementSelector elementSelector = new XPathElementSelector(expression, XPathModifier.Path);
        elementSelector.init(outputProcessorChain1);
        elementSelector.init(outputProcessorChain2);
        TreeWalker treeWalker1 = createTreeWalker(document1);

        XMLSecStartElement root1 = convertNodeToStartElement(treeWalker1.nextNode());
        processEvent(outputProcessorChain1, root1);
        assertThat(elementSelector.select(root1, outputProcessorChain1), is(false));
        processEvent(outputProcessorChain1, convertStartToEndElement(root1));
        TreeWalker treeWalker2 = createTreeWalker(document2);

        XMLSecStartElement root2 = convertNodeToStartElement(treeWalker2.nextNode());
        processEvent(outputProcessorChain2, root2);
        assertThat(elementSelector.select(root2, outputProcessorChain2), is(true));
        processEvent(outputProcessorChain2, convertStartToEndElement(root2));
    }
}