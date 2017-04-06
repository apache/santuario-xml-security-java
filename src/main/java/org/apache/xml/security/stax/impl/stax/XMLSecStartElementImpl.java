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
package org.apache.xml.security.stax.impl.stax;

import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecNamespace;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;

import javax.xml.namespace.NamespaceContext;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.Namespace;

import java.io.IOException;
import java.io.Writer;
import java.util.*;

/**
 */
public class XMLSecStartElementImpl extends XMLSecEventBaseImpl implements XMLSecStartElement {

    private final QName elementName;
    private XMLSecNamespace elementNamespace;
    private List<XMLSecAttribute> attributes = Collections.emptyList();
    private List<XMLSecNamespace> namespaces = Collections.emptyList();

    public XMLSecStartElementImpl(QName elementName, List<XMLSecAttribute> attributes, List<XMLSecNamespace> namespaces, XMLSecStartElement parentXmlSecStartElement) {
        this.elementName = elementName;
        setParentXMLSecStartElement(parentXmlSecStartElement);
        if (attributes != null) {
            this.attributes = attributes;
        }
        if (namespaces != null) {
            this.namespaces = namespaces;
        }
    }

    public XMLSecStartElementImpl(QName elementName, Collection<XMLSecAttribute> attributes, Collection<XMLSecNamespace> namespaces) {
        this.elementName = elementName;
        if (attributes != null && !attributes.isEmpty()) {
            this.attributes = new ArrayList<>(attributes);
        }
        if (namespaces != null && !namespaces.isEmpty()) {
            this.namespaces = new ArrayList<>(namespaces);
        }
    }

    @Override
    public QName getName() {
        return elementName;
    }

    @Override
    public XMLSecNamespace getElementNamespace() {
        if (this.elementNamespace == null) {
            this.elementNamespace = XMLSecNamespaceImpl.getInstance(this.elementName.getPrefix(), this.elementName.getNamespaceURI());
        }
        return this.elementNamespace;
    }

    @SuppressWarnings("unchecked")
    @Override
    public Iterator<Attribute> getAttributes() {
        if (attributes.isEmpty()) {
            return getEmptyIterator();
        }
        // Hack to get the code working with JDK9
        return (Iterator<Attribute>)(Iterator<?>)attributes.iterator();
    }

    @Override
    public void getAttributesFromCurrentScope(List<XMLSecAttribute> comparableAttributeList) {
        comparableAttributeList.addAll(attributes);
        if (parentXMLSecStartELement != null) {
            parentXMLSecStartELement.getAttributesFromCurrentScope(comparableAttributeList);
        }
    }

    @Override
    public List<XMLSecAttribute> getOnElementDeclaredAttributes() {
        return this.attributes;
    }

    @Override
    public void addAttribute(XMLSecAttribute xmlSecAttribute) {
        if (this.attributes == Collections.<XMLSecAttribute>emptyList()) {
            this.attributes = new ArrayList<>(1);
        }
        this.attributes.add(xmlSecAttribute);
    }

    @Override
    public int getDocumentLevel() {
        return super.getDocumentLevel() + 1;
    }

    @Override
    public void getElementPath(List<QName> list) {
        super.getElementPath(list);
        list.add(this.getName());
    }

    @Override
    public XMLSecStartElement getStartElementAtLevel(int level) {
        int thisLevel = getDocumentLevel();
        if (thisLevel < level) {
            return null;
        } else if (thisLevel == level) {
            return this;
        } else {
            return parentXMLSecStartELement.getStartElementAtLevel(level);
        }
    }

    @SuppressWarnings("unchecked")
    @Override
    public Iterator<Namespace> getNamespaces() {
        if (namespaces.isEmpty()) {
            return getEmptyIterator();
        }
        // Hack to get the code working with JDK9
        return (Iterator<Namespace>)(Iterator<?>)namespaces.iterator();
    }

    @Override
    public void getNamespacesFromCurrentScope(List<XMLSecNamespace> comparableNamespaceList) {
        if (parentXMLSecStartELement != null) {
            parentXMLSecStartELement.getNamespacesFromCurrentScope(comparableNamespaceList);
        }
        comparableNamespaceList.addAll(namespaces);
    }

    @Override
    public List<XMLSecNamespace> getOnElementDeclaredNamespaces() {
        return this.namespaces;
    }

    @Override
    public void addNamespace(XMLSecNamespace xmlSecNamespace) {
        if (this.namespaces == Collections.<XMLSecNamespace>emptyList()) {
            this.namespaces = new ArrayList<>(1);
        }
        this.namespaces.add(xmlSecNamespace);
    }

    @Override
    public Attribute getAttributeByName(QName name) {
        for (int i = 0; i < attributes.size(); i++) {
            Attribute comparableAttribute = attributes.get(i);
            if (name.equals(comparableAttribute.getName())) {
                return comparableAttribute;
            }
        }
        return null;
    }

    @Override
    public NamespaceContext getNamespaceContext() {
        return new NamespaceContext() {
            @Override
            public String getNamespaceURI(String prefix) {
                for (int i = 0; i < namespaces.size(); i++) {
                    Namespace comparableNamespace = namespaces.get(i);
                    if (prefix.equals(comparableNamespace.getPrefix())) {
                        return comparableNamespace.getNamespaceURI();
                    }
                }
                if (parentXMLSecStartELement != null) {
                    return parentXMLSecStartELement.getNamespaceURI(prefix);
                }
                return null;
            }

            @Override
            public String getPrefix(String namespaceURI) {
                for (int i = 0; i < namespaces.size(); i++) {
                    Namespace comparableNamespace = namespaces.get(i);
                    if (namespaceURI.equals(comparableNamespace.getNamespaceURI())) {
                        return comparableNamespace.getPrefix();
                    }
                }
                if (parentXMLSecStartELement != null) {
                    return parentXMLSecStartELement.getNamespaceContext().getPrefix(namespaceURI);
                }
                return null;
            }

            @SuppressWarnings("rawtypes")
            @Override
            public Iterator getPrefixes(String namespaceURI) {

                Set<String> prefixes = new HashSet<>();

                List<XMLSecNamespace> xmlSecNamespaces = new ArrayList<>();
                getNamespacesFromCurrentScope(xmlSecNamespaces);

                for (int i = 0; i < xmlSecNamespaces.size(); i++) {
                    Namespace xmlSecNamespace = xmlSecNamespaces.get(i);
                    if (namespaceURI.equals(xmlSecNamespace.getNamespaceURI())) {
                        prefixes.add(xmlSecNamespace.getPrefix());
                    }
                }
                return prefixes.iterator();
            }
        };
    }

    @Override
    public String getNamespaceURI(String prefix) {
        for (int i = 0; i < namespaces.size(); i++) {
            Namespace comparableNamespace = namespaces.get(i);
            if (prefix.equals(comparableNamespace.getPrefix())) {
                return comparableNamespace.getNamespaceURI();
            }
        }
        if (parentXMLSecStartELement != null) {
            return parentXMLSecStartELement.getNamespaceURI(prefix);
        }
        return null;
    }

    @Override
    public int getEventType() {
        return XMLStreamConstants.START_ELEMENT;
    }

    @Override
    public boolean isStartElement() {
        return true;
    }

    @Override
    public XMLSecStartElement asStartElement() {
        return this;
    }

    @Override
    public void writeAsEncodedUnicode(Writer writer) throws XMLStreamException {
        try {
            writer.write('<');
            final String prefix = getName().getPrefix();
            if (prefix != null && !prefix.isEmpty()) {
                writer.write(prefix);
                writer.write(':');
            }
            writer.write(getName().getLocalPart());

            for (Namespace xmlSecNamespace : namespaces) {
                writer.write(" xmlns");

                final String nsPrefix = xmlSecNamespace.getPrefix();
                if (nsPrefix != null && !nsPrefix.isEmpty()) {
                    writer.write(':');
                    writer.write(nsPrefix);
                }
                writer.write("=\"");
                writer.write(xmlSecNamespace.getValue());
                writer.write('"');
            }

            for (Attribute xmlSecAttribute : attributes) {
                writer.write(' ');
                final String attrPrefix = xmlSecAttribute.getName().getPrefix();
                if (attrPrefix != null && !attrPrefix.isEmpty()) {
                    writer.write(attrPrefix);
                    writer.write(':');
                }
                writer.write(xmlSecAttribute.getName().getLocalPart());
                writer.write("=\"");
                writer.write(xmlSecAttribute.getValue());
                writer.write('"');
            }

            writer.write('>');
        } catch (IOException e) {
            throw new XMLStreamException(e);
        }
    }
}
