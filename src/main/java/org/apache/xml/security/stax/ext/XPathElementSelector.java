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
package org.apache.xml.security.stax.ext;

import java.util.Optional;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.processor.output.XMLEncryptOutputProcessor;
import org.apache.xml.security.stax.impl.processor.output.XMLSignatureOutputProcessor;
import org.apache.xml.security.utils.DOMNamespaceContext;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static java.util.Objects.requireNonNull;
import static javax.xml.xpath.XPathConstants.NODESET;

/**
 * This class selects elements to secure based on a given XPath expression.
 * Properties:
 * <ul>
 *     <li>
 *         Limitations in terms of supported XPath expressions are inherited from the given {@link XPathFactory}.
 *         Typically, when using the JDK's built-in default, this means that support is limited to
 *         <a href="https://www.w3.org/TR/1999/REC-xpath-19991116/">XPath 1.0</a>, which is adequate to cover most use
 *         cases.
 *     </li>
 *     <li>
 *         Only elements (element nodes) can be selected.
 *         Expressions that select attributes (attribute nodes) will select nothing.
 *     </li>
 *     <li>
 *         Expressions that match elements and attributes are supported.
 *         Expressions that match content are not supported, because the skeleton DOM element dos not preserve content.
 *     </li>
 *     <li>
 *         Some expressions require the whole path up to the document root, or even all the siblings in order to be
 *         evaluated correctly. Such expressions will only work correctly when combined with {@link XPathModifier#Path}
 *         or {@link XPathModifier#Tree}.
 *     </li>
 * </ul>
 * Examples:
 * <table>
 *     <tr>
 *         <th>XPath expression</th>
 *         <th>Description</th>
 *     </tr>
 *     <tr>
 *         <td>/*</td>
 *         <td>Selects the root element.</td>
 *     </tr>
 *     <tr>
 *         <td>//element</td>
 *         <td>Selects elements without namespace URI or prefix matching a given local name.</td>
 *     </tr>
 *     <tr>
 *         <td>//*[@attr='value']</td>
 *         <td>Selects elements that have an attribute matching a given value.</td>
 *     </tr>
 *     <tr>
 *         <td>//*[namespace-uri() = 'urn:ns0' and local-name() = 'element']</td>
 *         <td>Selects elements matching a given namespace URI and local name, regardless of prefix.</td>
 *     </tr>
 *     <tr>
 *         <td>//element[2]</td>
 *         <td>
 *             Selects the second element matching a given (local) name. The index is 1-offset.
 *             This only works well in combination with {@link XPathModifier#Tree}, which must be used with care.
 *         </td>
 *     </tr>
 * </table>
 */
public class XPathElementSelector implements ElementSelector {

    private static final class LazilyInitializedXPathFactory {

        private static final XPathFactory INSTANCE = XPathFactory.newInstance();
    }

    private static XPathFactory getXPathFactoryInstance() {
        return LazilyInitializedXPathFactory.INSTANCE;
    }

    private final XPathFactory xPathFactory;
    private final String expression;
    private final XPathModifier modifier;

    private static class Context {

        Document document;
        DOMNamespaceContext namespaceContext;
        XPath xPath;
    }

    /**
     * Constructs an XPath element selector using a given expression and modifier.
     * It uses the default Java XPath factory, which is limited to XPath 1.0 expressions (in Java 11).
     *
     * @param expression An XPath 1.0 expression, which must not be {@code null}.
     * @param modifier An XPath modifier, which must not be {@code null}.
     */
    public XPathElementSelector(String expression, XPathModifier modifier) {
        this(getXPathFactoryInstance(), expression, modifier);
    }

    /**
     * Constructs an XPath element selector using a given XPath factory, expression and modifier.
     * The expression must be compatible with the XPath factory.
     * If for example the XPath factory is limited to XPath 1.0, then the expression is subject to that same limitation.
     *
     * @param xPathFactory An XPath factory, which must not be {@code null}.
     * @param expression An XPath expression, which must not be {@code null}.
     *                   Because the expression is lazily evaluated, it will not be validated until first use.
     *                   Because namespace resolution may be required to evaluate it correctly, which can only be done
     *                   while streaming the document, there is no point in trying to validate it upfront either.
     * @param modifier An XPath modifier, which must not be {@code null}.
     */
    public XPathElementSelector(XPathFactory xPathFactory, String expression, XPathModifier modifier) {
        requireNonNull(xPathFactory, "XPath factory is null");
        requireNonNull(expression, "XPath expression is null");
        requireNonNull(modifier, "XPath modifier is null");
        this.xPathFactory = xPathFactory;
        this.expression = expression;
        this.modifier = modifier;
    }

    @Override
    public void init(OutputProcessorChain outputProcessorChain) {
        Optional<OutputProcessor> optionalOutputProcessor = outputProcessorChain.getProcessors().stream().filter(outputProcessor -> outputProcessor instanceof XPathOutputProcessor).findAny();
        if (optionalOutputProcessor.isPresent()) {
            XPathOutputProcessor xPathOutputProcessor = (XPathOutputProcessor) optionalOutputProcessor.get();
            if (xPathOutputProcessor.getModifier().ordinal() >= modifier.ordinal()) {
                // One XPath output processor per chain is enough.
                // If it has at least the required modifier, keep it ...
                return;
            }
            // ... otherwise, remove it and replace it with another one.
            outputProcessorChain.removeProcessor(xPathOutputProcessor);
        }
        AbstractOutputProcessor xPathOutputProcessor = new XPathOutputProcessor(modifier);
        xPathOutputProcessor.addBeforeProcessor(XMLSignatureOutputProcessor.class);
        xPathOutputProcessor.addBeforeProcessor(XMLEncryptOutputProcessor.class);
        outputProcessorChain.addProcessor(xPathOutputProcessor);
        outputProcessorChain.getSecurityContext().put(Context.class, new Context());
    }

    @Override
    public boolean select(XMLSecStartElement startElement, OutputProcessorChain outputProcessorChain) {
        OutboundSecurityContext securityContext = outputProcessorChain.getSecurityContext();
        Element element = securityContext.get(Element.class);
        if (element == null) {
            return false;
        }
        Context c = securityContext.get(Context.class);
        Document document = element.getOwnerDocument();
        if (c.xPath != null && !document.equals(c.document)) {
            c.xPath = null;
            c.namespaceContext = null;
        }
        c.document = document;
        if (c.namespaceContext == null) {
            c.namespaceContext = new DOMNamespaceContext(element);
        } else {
            c.namespaceContext.setContext(element);
        }
        if (c.xPath == null) {
            c.xPath = xPathFactory.newXPath();
            c.xPath.setNamespaceContext(c.namespaceContext);
        }
        try {
            XPathExpression xPathExpression = c.xPath.compile(expression);
            NodeList nodes = (NodeList) xPathExpression.evaluate(document, NODESET);
            for (int i = 0, n = nodes.getLength(); i != n; i++) {
                if (nodes.item(i) == element) {
                    return true;
                }
            }
        } catch (XPathExpressionException ignored) {
            // This can happen if e.g. the XPath expression contains namespaces that have not yet been resolved
            // because their definition has not been reached in the document yet.
        }
        return false;
    }

    /**
     * @return The XPath expression, never {@code null}.
     */
    @Override
    public String toString() {
        return expression;
    }
}
