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
package org.apache.xml.security.stax.ext.stax;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.events.EntityDeclaration;

import org.apache.xml.security.stax.impl.stax.XMLSecAttributeImpl;
import org.apache.xml.security.stax.impl.stax.XMLSecCharactersImpl;
import org.apache.xml.security.stax.impl.stax.XMLSecCommentImpl;
import org.apache.xml.security.stax.impl.stax.XMLSecDTDImpl;
import org.apache.xml.security.stax.impl.stax.XMLSecEndDocumentImpl;
import org.apache.xml.security.stax.impl.stax.XMLSecEndElementImpl;
import org.apache.xml.security.stax.impl.stax.XMLSecEntityDeclarationImpl;
import org.apache.xml.security.stax.impl.stax.XMLSecEntityReferenceImpl;
import org.apache.xml.security.stax.impl.stax.XMLSecNamespaceImpl;
import org.apache.xml.security.stax.impl.stax.XMLSecProcessingInstructionImpl;
import org.apache.xml.security.stax.impl.stax.XMLSecStartDocumentImpl;
import org.apache.xml.security.stax.impl.stax.XMLSecStartElementImpl;

/**
 */
public final class XMLSecEventFactory {

    private XMLSecEventFactory() {
    }

    public static XMLSecEvent allocate(XMLStreamReader xmlStreamReader, XMLSecStartElement parentXMLSecStartElement) throws XMLStreamException {
        switch (xmlStreamReader.getEventType()) {
            case XMLStreamConstants.START_ELEMENT: {
                List<XMLSecAttribute> comparableAttributes = null;
                final int attributeCount = xmlStreamReader.getAttributeCount();
                if (attributeCount > 0) {
                    comparableAttributes = new ArrayList<>(attributeCount);
                    for (int i = 0; i < attributeCount; i++) {
                        comparableAttributes.add(XMLSecEventFactory.createXMLSecAttribute(xmlStreamReader.getAttributeName(i), xmlStreamReader.getAttributeValue(i)));
                    }
                }

                List<XMLSecNamespace> comparableNamespaces = null;
                final int namespaceCount = xmlStreamReader.getNamespaceCount();
                if (namespaceCount > 0) {
                    comparableNamespaces = new ArrayList<>(namespaceCount);
                    for (int i = 0; i < namespaceCount; i++) {
                        comparableNamespaces.add(XMLSecNamespaceImpl.getInstance(xmlStreamReader.getNamespacePrefix(i), xmlStreamReader.getNamespaceURI(i)));
                    }
                }
                return new XMLSecStartElementImpl(xmlStreamReader.getName(), comparableAttributes, comparableNamespaces, parentXMLSecStartElement);
            }
            case XMLStreamConstants.END_ELEMENT:
                return new XMLSecEndElementImpl(xmlStreamReader.getName(), parentXMLSecStartElement);
            case XMLStreamConstants.PROCESSING_INSTRUCTION:
                return new XMLSecProcessingInstructionImpl(xmlStreamReader.getPITarget(), xmlStreamReader.getPIData(), parentXMLSecStartElement);
            case XMLStreamConstants.CHARACTERS:
                final char[] text = new char[xmlStreamReader.getTextLength()];
                xmlStreamReader.getTextCharacters(0, text, 0, xmlStreamReader.getTextLength());
                return new XMLSecCharactersImpl(text, false, false, xmlStreamReader.isWhiteSpace(), parentXMLSecStartElement);
            case XMLStreamConstants.COMMENT:
                return new XMLSecCommentImpl(xmlStreamReader.getText(), parentXMLSecStartElement);
            case XMLStreamConstants.SPACE:
                return new XMLSecCharactersImpl(xmlStreamReader.getText(), false, true, xmlStreamReader.isWhiteSpace(), parentXMLSecStartElement);
            case XMLStreamConstants.START_DOCUMENT:
                final String systemId = xmlStreamReader.getLocation() != null ? xmlStreamReader.getLocation().getSystemId() : null;
                return new XMLSecStartDocumentImpl(systemId, xmlStreamReader.getCharacterEncodingScheme(),
                        xmlStreamReader.standaloneSet() ? xmlStreamReader.isStandalone() : null, xmlStreamReader.getVersion());
            case XMLStreamConstants.END_DOCUMENT:
                return new XMLSecEndDocumentImpl();
            case XMLStreamConstants.ENTITY_REFERENCE:
                return new XMLSecEntityReferenceImpl(xmlStreamReader.getLocalName(), null, parentXMLSecStartElement);
            case XMLStreamConstants.ATTRIBUTE:
                throw new UnsupportedOperationException("Attribute event not supported");
            case XMLStreamConstants.DTD:
                return new XMLSecDTDImpl(xmlStreamReader.getText(), parentXMLSecStartElement);
            case XMLStreamConstants.CDATA:
                return new XMLSecCharactersImpl(xmlStreamReader.getText(), false, false, xmlStreamReader.isWhiteSpace(), parentXMLSecStartElement);
            case XMLStreamConstants.NAMESPACE:
                throw new UnsupportedOperationException("Namespace event not supported");
            case XMLStreamConstants.NOTATION_DECLARATION:
                throw new UnsupportedOperationException("NotationDeclaration event not supported");
            case XMLStreamConstants.ENTITY_DECLARATION:
                throw new UnsupportedOperationException("Entity declaration event not supported");
        }
        throw new IllegalArgumentException("Unknown XML event occurred");
    }

    public static XMLSecStartElement createXmlSecStartElement(QName name, List<XMLSecAttribute> attributes, List<XMLSecNamespace> namespaces) {
        return new XMLSecStartElementImpl(name, attributes, namespaces);
    }

    public static XMLSecStartElement createXmlSecStartElement(QName name, Collection<XMLSecAttribute> attributes, Collection<XMLSecNamespace> namespaces) {
        return new XMLSecStartElementImpl(name, attributes, namespaces);
    }

    public static XMLSecEndElement createXmlSecEndElement(QName name) {
        return new XMLSecEndElementImpl(name, null);
    }

    public static XMLSecStartDocument createXmlSecStartDocument(String systemId, String characterEncodingScheme, Boolean standAlone, String version) {
        return new XMLSecStartDocumentImpl(systemId, characterEncodingScheme, standAlone, version);
    }

    public static XMLSecEndDocument createXMLSecEndDocument() {
        return new XMLSecEndDocumentImpl();
    }

    public static XMLSecCharacters createXmlSecCharacters(String data) {
        return new XMLSecCharactersImpl(data, false, false, false, null);
    }

    public static XMLSecCharacters createXmlSecCharacters(char[] text) {
        return new XMLSecCharactersImpl(text, false, false, false, null);
    }

    public static XMLSecCharacters createXmlSecCharacters(char[] text, int off, int len) {
        return new XMLSecCharactersImpl(Arrays.copyOfRange(text, off, off + len), false, false, false, null);
    }

    public static XMLSecComment createXMLSecComment(String data) {
        return new XMLSecCommentImpl(data, null);
    }

    public static XMLSecProcessingInstruction createXMLSecProcessingInstruction(String target, String data) {
        return new XMLSecProcessingInstructionImpl(target, data, null);
    }

    public static XMLSecCharacters createXMLSecCData(String data) {
        return new XMLSecCharactersImpl(data, true, false, false, null);
    }

    public static XMLSecDTD createXMLSecDTD(String dtd) {
        return new XMLSecDTDImpl(dtd, null);
    }

    public static XMLSecEntityReference createXMLSecEntityReference(String name, EntityDeclaration entityDeclaration) {
        return new XMLSecEntityReferenceImpl(name, entityDeclaration, null);
    }

    public static XMLSecEntityDeclaration createXmlSecEntityDeclaration(String name) {
        return new XMLSecEntityDeclarationImpl(name);
    }

    public static XMLSecAttribute createXMLSecAttribute(QName name, String value) {
        return new XMLSecAttributeImpl(name, value);
    }

    public static XMLSecNamespace createXMLSecNamespace(String prefix, String uri) {
        return XMLSecNamespaceImpl.getInstance(prefix, uri);
    }
}
