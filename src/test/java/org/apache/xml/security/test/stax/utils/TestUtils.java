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
package org.apache.xml.security.test.stax.utils;

import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import javax.xml.XMLConstants;
import javax.xml.namespace.QName;

import org.apache.xml.security.stax.ext.OutboundSecurityContext;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.SecurePartSelector;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecNamespace;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.OutboundSecurityContextImpl;
import org.apache.xml.security.stax.impl.OutputProcessorChainImpl;
import org.apache.xml.security.stax.impl.stax.XMLSecAttributeImpl;
import org.apache.xml.security.stax.impl.stax.XMLSecNamespaceImpl;
import org.apache.xml.security.stax.impl.stax.XMLSecStartElementImpl;
import org.apache.xml.security.utils.KeyValue;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeDiagnosingMatcher;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.traversal.DocumentTraversal;
import org.w3c.dom.traversal.NodeFilter;
import org.w3c.dom.traversal.TreeWalker;

public class TestUtils {

    public static List<SecurePart> toSecureParts(Document document, List<SecurePartSelector> securePartSelectors) {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        OutboundSecurityContext securityContext = new OutboundSecurityContextImpl(properties);
        OutputProcessorChain outputProcessorChain = new OutputProcessorChainImpl(securityContext);
        List<SecurePart> secureParts = new ArrayList<>(securePartSelectors.size());
        TreeWalker walker = ((DocumentTraversal) document).createTreeWalker(document.getDocumentElement(), NodeFilter.SHOW_ELEMENT, null, true);
        Map<Node, XMLSecStartElement> elementsByNode = new IdentityHashMap<>();
        for (Node node = walker.getCurrentNode(); node != null; node = walker.nextNode()) {
            QName name = convertNodeToQName(node);
            KeyValue<List<XMLSecAttribute>, List<XMLSecNamespace>> attributesAndNamespaces = convertNodeToAttributesAndNamespaces(node);
            List<XMLSecAttribute> attributes = attributesAndNamespaces.getKey();
            List<XMLSecNamespace> namespaces = attributesAndNamespaces.getValue();
            XMLSecStartElement parent = elementsByNode.get(node.getParentNode());
            XMLSecStartElement element = new XMLSecStartElementImpl(name, attributes, namespaces, parent);
            elementsByNode.put(node, element);
            for (SecurePartSelector securePartSelector : securePartSelectors) {
                SecurePart securePart = securePartSelector.select(element, outputProcessorChain);
                if (securePart != null) {
                    secureParts.add(securePart);
                    break;
                }
            }
        }
        return secureParts;
    }

    public static Matcher<String> containsRegex(String pattern) {
        return containsRegex(pattern, true, 1);
    }

    public static Matcher<String> containsRegex(Pattern pattern) {
        return containsRegex(pattern, true, 1);
    }

    public static Matcher<String> containsRegex(String pattern, int times) {
        return containsRegex(pattern, false, times);
    }

    public static Matcher<String> containsRegex(Pattern pattern, int times) {
        return containsRegex(pattern, false, times);
    }

    public static Matcher<String> containsRegex(String pattern, boolean atLeast, int times) {
        return containsRegex(Pattern.compile(pattern), atLeast, times);
    }

    public static Matcher<String> containsRegex(Pattern pattern, boolean atLeast, int times) {
        return new TypeSafeDiagnosingMatcher<String>() {

            @Override
            public void describeTo(Description description) {
                description.appendText("a string containing the pattern ").appendValue(pattern)
                        .appendText(atLeast ? " at least " : " exactly ").appendValue(times).appendText(" times");
            }

            @Override
            protected boolean matchesSafely(String actual, Description mismatchDescription) {
                java.util.regex.Matcher matcher = pattern.matcher(actual);
                int found = 0;
                while (matcher.find()) {
                    found++;
                }
                boolean matches = atLeast ? found >= times : found == times;
                if (!matches) {
                    mismatchDescription.appendText("the string was ").appendValue(actual);
                }
                return matches;
            }
        };
    }

    public static QName convertNodeToQName(Node node) {
        String namespaceURI = node.getNamespaceURI();
        if (namespaceURI == null) {
            namespaceURI = XMLConstants.NULL_NS_URI;
        }
        String prefix = node.getPrefix();
        if (prefix == null) {
            prefix = XMLConstants.DEFAULT_NS_PREFIX;
        }
        String localName = node.getLocalName();
        if (localName == null) {
            throw new IllegalArgumentException("Local name is null, indicating that DOM level 2 is not supported while it is required. If created using a DocumentBuilder, be sure to setNamespaceAware(true).");
        }
        return new QName(namespaceURI, localName, prefix);
    }

    public static KeyValue<List<XMLSecAttribute>, List<XMLSecNamespace>> convertNodeToAttributesAndNamespaces(Node node) {
        NamedNodeMap attributesAndNamespaces = node.getAttributes();
        List<XMLSecAttribute> attributes = new ArrayList<>(attributesAndNamespaces.getLength());
        List<XMLSecNamespace> namespaces = new ArrayList<>(attributesAndNamespaces.getLength());
        for (int i = 0, n = attributesAndNamespaces.getLength(); i != n; i++) {
            Attr attr = (Attr) attributesAndNamespaces.item(i);
            if (attr.getName().equals("xmlns")) {
                namespaces.add(XMLSecNamespaceImpl.getInstance(null, attr.getValue()));
            } else if (attr.getName().startsWith("xmlns:")) {
                namespaces.add(XMLSecNamespaceImpl.getInstance(attr.getName().substring(6), attr.getValue()));
            } else {
                QName name = convertNodeToQName(attr);
                attributes.add(new XMLSecAttributeImpl(name, attr.getValue()));
            }
        }
        return new KeyValue<>(attributes, namespaces);
    }
}
