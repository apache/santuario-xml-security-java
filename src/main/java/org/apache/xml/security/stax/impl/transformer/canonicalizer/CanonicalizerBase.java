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
package org.apache.xml.security.stax.impl.transformer.canonicalizer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;

import org.apache.xml.security.c14n.implementations.UtfHelpper;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.Transformer;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityUtils;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecComment;
import org.apache.xml.security.stax.ext.stax.XMLSecEndElement;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecEventFactory;
import org.apache.xml.security.stax.ext.stax.XMLSecNamespace;
import org.apache.xml.security.stax.ext.stax.XMLSecProcessingInstruction;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.processor.input.XMLEventReaderInputProcessor;
import org.apache.xml.security.stax.impl.transformer.TransformIdentity;
import org.apache.xml.security.utils.UnsyncByteArrayInputStream;
import org.apache.xml.security.utils.UnsyncByteArrayOutputStream;

/**
 */
public abstract class CanonicalizerBase extends TransformIdentity {

    static final byte[] _END_PI = {'?', '>'};
    static final byte[] _BEGIN_PI = {'<', '?'};
    static final byte[] _END_COMM = {'-', '-', '>'};
    static final byte[] _BEGIN_COMM = {'<', '!', '-', '-'};
    static final byte[] __XA_ = {'&', '#', 'x', 'A', ';'};
    static final byte[] __X9_ = {'&', '#', 'x', '9', ';'};
    static final byte[] _QUOT_ = {'&', 'q', 'u', 'o', 't', ';'};
    static final byte[] __XD_ = {'&', '#', 'x', 'D', ';'};
    static final byte[] _GT_ = {'&', 'g', 't', ';'};
    static final byte[] _LT_ = {'&', 'l', 't', ';'};
    static final byte[] _END_TAG = {'<', '/'};
    static final byte[] _AMP_ = {'&', 'a', 'm', 'p', ';'};
    static final byte[] EQUAL_STRING = {'=', '\"'};
    static final byte[] NEWLINE = {'\n'};

    protected static final String XML = "xml";
    protected static final String XMLNS = "xmlns";
    protected static final char DOUBLEPOINT = ':';

    private enum DocumentLevel {
        NODE_BEFORE_DOCUMENT_ELEMENT,
        NODE_NOT_BEFORE_OR_AFTER_DOCUMENT_ELEMENT,
        NODE_AFTER_DOCUMENT_ELEMENT
    }

    private static final Map<String, byte[]> CACHE = Collections.synchronizedMap(new WeakHashMap<String, byte[]>());
    private final C14NStack<XMLSecEvent> outputStack = new C14NStack<>();
    private boolean includeComments = false;
    private DocumentLevel currentDocumentLevel = DocumentLevel.NODE_BEFORE_DOCUMENT_ELEMENT;

    protected boolean firstCall = true;

    public CanonicalizerBase(boolean includeComments) {
        this.includeComments = includeComments;
    }

    @Override
    public void setProperties(Map<String, Object> properties) throws XMLSecurityException {
        throw new UnsupportedOperationException("InclusiveNamespace-PrefixList not supported");
    }

    @Override
    public void setTransformer(Transformer transformer) throws XMLSecurityException {
        //we support only transformers which takes an InputStream otherwise we will break the C14N
        setOutputStream(new UnsyncByteArrayOutputStream());
        super.setTransformer(transformer);
    }

    protected List<XMLSecNamespace> getCurrentUtilizedNamespaces(final XMLSecStartElement xmlSecStartElement,
                                                                      final C14NStack<XMLSecEvent> outputStack) {

        List<XMLSecNamespace> utilizedNamespaces = Collections.emptyList();

        XMLSecNamespace elementNamespace = xmlSecStartElement.getElementNamespace();
        final XMLSecNamespace found = (XMLSecNamespace) outputStack.containsOnStack(elementNamespace);
        //found means the prefix matched. so check the ns further
        if (found == null || found.getNamespaceURI() == null
                || !found.getNamespaceURI().equals(elementNamespace.getNamespaceURI())) {

            utilizedNamespaces = new ArrayList<>(2);
            utilizedNamespaces.add(elementNamespace);
            outputStack.peek().add(elementNamespace);
        }

        List<XMLSecNamespace> declaredNamespaces = xmlSecStartElement.getOnElementDeclaredNamespaces();
        for (int i = 0; i < declaredNamespaces.size(); i++) {
            XMLSecNamespace comparableNamespace = declaredNamespaces.get(i);
            final XMLSecNamespace resultNamespace = (XMLSecNamespace) outputStack.containsOnStack(comparableNamespace);
            //resultNamespace means the prefix matched. so check the ns further
            if (resultNamespace != null && resultNamespace.getNamespaceURI() != null
                    && resultNamespace.getNamespaceURI().equals(comparableNamespace.getNamespaceURI())) {
                continue;
            }

            if (utilizedNamespaces == Collections.<XMLSecNamespace>emptyList()) {
                utilizedNamespaces = new ArrayList<>(2);
            }
            utilizedNamespaces.add(comparableNamespace);
            outputStack.peek().add(comparableNamespace);
        }

        List<XMLSecAttribute> comparableAttributes = xmlSecStartElement.getOnElementDeclaredAttributes();
        for (int i = 0; i < comparableAttributes.size(); i++) {
            XMLSecAttribute xmlSecAttribute = comparableAttributes.get(i);
            XMLSecNamespace attributeNamespace = xmlSecAttribute.getAttributeNamespace();
            if ("xml".equals(attributeNamespace.getPrefix())) {
                continue;
            }
            if (attributeNamespace.getNamespaceURI() == null || attributeNamespace.getNamespaceURI().isEmpty()) {
                continue;
            }
            final XMLSecNamespace resultNamespace = (XMLSecNamespace) outputStack.containsOnStack(attributeNamespace);
            //resultNamespace means the prefix matched. so check the ns further
            if (resultNamespace == null || resultNamespace.getNamespaceURI() == null
                    || !resultNamespace.getNamespaceURI().equals(attributeNamespace.getNamespaceURI())) {

                if (utilizedNamespaces == Collections.<XMLSecNamespace>emptyList()) {
                    utilizedNamespaces = new ArrayList<>(2);
                }
                utilizedNamespaces.add(attributeNamespace);
                outputStack.peek().add(attributeNamespace);
            }
        }

        return utilizedNamespaces;
    }

    protected List<XMLSecAttribute> getCurrentUtilizedAttributes(final XMLSecStartElement xmlSecStartElement,
                                                                      final C14NStack<XMLSecEvent> outputStack) {
        List<XMLSecAttribute> comparableAttributes = xmlSecStartElement.getOnElementDeclaredAttributes();
        if (comparableAttributes.isEmpty()) {
            return Collections.emptyList();
        }

        return new ArrayList<>(comparableAttributes);
    }

    protected List<XMLSecNamespace> getInitialUtilizedNamespaces(final XMLSecStartElement xmlSecStartElement,
                                                                      final C14NStack<XMLSecEvent> outputStack) {

        final List<XMLSecNamespace> utilizedNamespaces = new ArrayList<>();
        List<XMLSecNamespace> visibleNamespaces = new ArrayList<>();
        xmlSecStartElement.getNamespacesFromCurrentScope(visibleNamespaces);
        for (int i = 0; i < visibleNamespaces.size(); i++) {
            XMLSecNamespace comparableNamespace = visibleNamespaces.get(i);

            final XMLSecNamespace found = (XMLSecNamespace) outputStack.containsOnStack(comparableNamespace);
            //found means the prefix matched. so check the ns further
            if (found != null) {
                //ns redefinition so remove the old one:
                //remove(comparableNamespace) works because we have overwritten the hash and equals method and just test
                //for prefix equality
                utilizedNamespaces.remove(comparableNamespace);
            }
            outputStack.peek().add(comparableNamespace);

            //don't add xmlns="" declarations:
            if (!comparableNamespace.getNamespaceURI().isEmpty() || !comparableNamespace.getPrefix().isEmpty()) {
                utilizedNamespaces.add(comparableNamespace);
            }
        }

        return utilizedNamespaces;
    }

    protected List<XMLSecAttribute> getInitialUtilizedAttributes(final XMLSecStartElement xmlSecStartElement,
                                                                      final C14NStack<XMLSecEvent> outputStack) {

        List<XMLSecAttribute> utilizedAttributes = Collections.emptyList();

        List<XMLSecAttribute> comparableAttributes = new ArrayList<>();
        xmlSecStartElement.getAttributesFromCurrentScope(comparableAttributes);
        for (int i = 0; i < comparableAttributes.size(); i++) {
            XMLSecAttribute comparableAttribute = comparableAttributes.get(i);
            if (!XML.equals(comparableAttribute.getName().getPrefix())) {
                continue;
            }
            if (outputStack.containsOnStack(comparableAttribute) != null) {
                continue;
            }
            if (utilizedAttributes == Collections.<XMLSecAttribute>emptyList()) {
                utilizedAttributes = new ArrayList<>(2);
            }
            utilizedAttributes.add(comparableAttribute);
            outputStack.peek().add(comparableAttribute);
        }

        List<XMLSecAttribute> elementAttributes = xmlSecStartElement.getOnElementDeclaredAttributes();
        for (int i = 0; i < elementAttributes.size(); i++) {
            XMLSecAttribute comparableAttribute = elementAttributes.get(i);
            //attributes with xml prefix are already processed in the for loop above
            //xml:id attributes must be handled like other attributes: emit but dont inherit
            final QName attributeName = comparableAttribute.getName();
            if (XML.equals(attributeName.getPrefix())) {
                continue;
            }
            if (utilizedAttributes == Collections.<XMLSecAttribute>emptyList()) {
                utilizedAttributes = new ArrayList<>(2);
            }
            utilizedAttributes.add(comparableAttribute);
        }
        return utilizedAttributes;
    }

    @Override
    public XMLSecurityConstants.TransformMethod getPreferredTransformMethod(XMLSecurityConstants.TransformMethod forInput) {
        switch (forInput) {
            case XMLSecEvent:
                return XMLSecurityConstants.TransformMethod.XMLSecEvent;
            case InputStream:
                return XMLSecurityConstants.TransformMethod.InputStream;
            default:
                throw new IllegalArgumentException("Unsupported class " + forInput.name());
        }
    }

    @Override
    public void transform(final XMLSecEvent xmlSecEvent) throws XMLStreamException {
        try {
            OutputStream outputStream = getOutputStream();  //NOPMD

            switch (xmlSecEvent.getEventType()) {
                case XMLStreamConstants.START_ELEMENT:

                    final XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();

                    currentDocumentLevel = DocumentLevel.NODE_NOT_BEFORE_OR_AFTER_DOCUMENT_ELEMENT;
                    outputStack.push(Collections.<Comparable>emptyList());

                    final List<XMLSecNamespace> utilizedNamespaces;
                    final List<XMLSecAttribute> utilizedAttributes;

                    if (firstCall) {
                        utilizedNamespaces = new ArrayList<>();
                        utilizedAttributes = new ArrayList<>();
                        outputStack.peek().add(XMLSecEventFactory.createXMLSecNamespace(null, ""));
                        outputStack.push(Collections.<Comparable>emptyList());

                        utilizedNamespaces.addAll(getInitialUtilizedNamespaces(xmlSecStartElement, outputStack));
                        utilizedAttributes.addAll(getInitialUtilizedAttributes(xmlSecStartElement, outputStack));

                        firstCall = false;
                    } else {
                        utilizedNamespaces = getCurrentUtilizedNamespaces(xmlSecStartElement, outputStack);
                        utilizedAttributes = getCurrentUtilizedAttributes(xmlSecStartElement, outputStack);
                    }

                    outputStream.write('<');
                    final String prefix = xmlSecStartElement.getName().getPrefix();
                    if (prefix != null && !prefix.isEmpty()) {
                        UtfHelpper.writeByte(prefix, outputStream, CACHE);
                        outputStream.write(DOUBLEPOINT);
                    }
                    final String name = xmlSecStartElement.getName().getLocalPart();
                    UtfHelpper.writeByte(name, outputStream, CACHE);

                    if (!utilizedNamespaces.isEmpty()) {
                        Collections.sort(utilizedNamespaces);
                        for (int i = 0; i < utilizedNamespaces.size(); i++) {
                            final XMLSecNamespace xmlSecNamespace = utilizedNamespaces.get(i);
                            if (!namespaceIsAbsolute(xmlSecNamespace.getNamespaceURI())) {
                                throw new XMLStreamException("namespace is relative encountered: " + xmlSecNamespace.getNamespaceURI());
                            }

                            if (xmlSecNamespace.isDefaultNamespaceDeclaration()) {
                                outputAttrToWriter(null, XMLNS, xmlSecNamespace.getNamespaceURI(), outputStream, CACHE);
                            } else {
                                outputAttrToWriter(XMLNS, xmlSecNamespace.getPrefix(), xmlSecNamespace.getNamespaceURI(), outputStream, CACHE);
                            }
                        }
                    }

                    if (!utilizedAttributes.isEmpty()) {
                        Collections.sort(utilizedAttributes);
                        for (int i = 0; i < utilizedAttributes.size(); i++) {
                            final XMLSecAttribute xmlSecAttribute = utilizedAttributes.get(i);

                            final QName attributeName = xmlSecAttribute.getName();
                            final String attributeNamePrefix = attributeName.getPrefix();
                            if (attributeNamePrefix != null && !attributeNamePrefix.isEmpty()) {
                                outputAttrToWriter(attributeNamePrefix, attributeName.getLocalPart(), xmlSecAttribute.getValue(), outputStream, CACHE);
                            } else {
                                outputAttrToWriter(null, attributeName.getLocalPart(), xmlSecAttribute.getValue(), outputStream, CACHE);
                            }
                        }
                    }

                    outputStream.write('>');
                    break;
                case XMLStreamConstants.END_ELEMENT:
                    final XMLSecEndElement xmlSecEndElement = xmlSecEvent.asEndElement();
                    final String localPrefix = xmlSecEndElement.getName().getPrefix();
                    outputStream.write(_END_TAG);
                    if (localPrefix != null && !localPrefix.isEmpty()) {
                        UtfHelpper.writeByte(localPrefix, outputStream, CACHE);
                        outputStream.write(DOUBLEPOINT);
                    }
                    UtfHelpper.writeByte(xmlSecEndElement.getName().getLocalPart(), outputStream, CACHE);
                    outputStream.write('>');

                    //We finished with this level, pop to the previous definitions.
                    outputStack.pop();
                    if (outputStack.size() == 1) {
                        currentDocumentLevel = DocumentLevel.NODE_AFTER_DOCUMENT_ELEMENT;
                    }

                    break;
                case XMLStreamConstants.PROCESSING_INSTRUCTION:
                    outputPItoWriter((XMLSecProcessingInstruction) xmlSecEvent, outputStream, currentDocumentLevel);
                    break;
                case XMLStreamConstants.CHARACTERS:
                    if (currentDocumentLevel == DocumentLevel.NODE_NOT_BEFORE_OR_AFTER_DOCUMENT_ELEMENT) {
                        outputTextToWriter(xmlSecEvent.asCharacters().getText(), outputStream);
                    }
                    break;
                case XMLStreamConstants.COMMENT:
                    if (includeComments) {
                        outputCommentToWriter((XMLSecComment) xmlSecEvent, outputStream, currentDocumentLevel);
                    }
                    break;
                case XMLStreamConstants.SPACE:
                    if (currentDocumentLevel == DocumentLevel.NODE_NOT_BEFORE_OR_AFTER_DOCUMENT_ELEMENT) {
                        outputTextToWriter(xmlSecEvent.asCharacters().getText(), outputStream);
                    }
                    break;
                case XMLStreamConstants.START_DOCUMENT:
                    currentDocumentLevel = DocumentLevel.NODE_BEFORE_DOCUMENT_ELEMENT;
                    break;
                case XMLStreamConstants.END_DOCUMENT:
                    break;
                case XMLStreamConstants.ENTITY_REFERENCE:
                    throw new XMLStreamException("illegal event :" + XMLSecurityUtils.getXMLEventAsString(xmlSecEvent));
                case XMLStreamConstants.ATTRIBUTE:
                    throw new XMLStreamException("illegal event :" + XMLSecurityUtils.getXMLEventAsString(xmlSecEvent));
                case XMLStreamConstants.DTD:
                    break;
                case XMLStreamConstants.CDATA:
                    outputTextToWriter(xmlSecEvent.asCharacters().getData(), outputStream);
                    break;
                case XMLStreamConstants.NAMESPACE:
                    throw new XMLStreamException("illegal event :" + XMLSecurityUtils.getXMLEventAsString(xmlSecEvent));
                case XMLStreamConstants.NOTATION_DECLARATION:
                    throw new XMLStreamException("illegal event :" + XMLSecurityUtils.getXMLEventAsString(xmlSecEvent));
                case XMLStreamConstants.ENTITY_DECLARATION:
                    throw new XMLStreamException("illegal event :" + XMLSecurityUtils.getXMLEventAsString(xmlSecEvent));
            }
        } catch (IOException e) {
            throw new XMLStreamException(e);
        }
    }

    @Override
    public void transform(InputStream inputStream) throws XMLStreamException {
        XMLEventReaderInputProcessor xmlEventReaderInputProcessor =
                new XMLEventReaderInputProcessor(null, getXmlInputFactory().createXMLStreamReader(inputStream));

        try {
            XMLSecEvent xmlSecEvent;
            do {
                xmlSecEvent = xmlEventReaderInputProcessor.processEvent(null);
                this.transform(xmlSecEvent);
            } while (xmlSecEvent.getEventType() != XMLStreamConstants.END_DOCUMENT);
        } catch (XMLSecurityException e) {
            throw new XMLStreamException(e);
        }
    }

    @Override
    public void doFinal() throws XMLStreamException {
        if (getTransformer() != null) {
            UnsyncByteArrayOutputStream baos = (UnsyncByteArrayOutputStream)getOutputStream();  //NOPMD
            try (InputStream is = new UnsyncByteArrayInputStream(baos.toByteArray())) {
                getTransformer().transform(is);
                getTransformer().doFinal();
            } catch (IOException ex) {
                throw new XMLStreamException(ex);
            }
        }
    }

    protected static void outputAttrToWriter(final String prefix, final String name, final String value, final OutputStream writer,
                                             final Map<String, byte[]> CACHE) throws IOException {
        writer.write(' ');
        if (prefix != null) {
            UtfHelpper.writeByte(prefix, writer, CACHE);
            UtfHelpper.writeCodePointToUtf8(DOUBLEPOINT, writer);
        }
        UtfHelpper.writeByte(name, writer, CACHE);
        writer.write(EQUAL_STRING);
        byte[] toWrite;
        final int length = value.length();
        int i = 0;
        while (i < length) {
            final int c = value.codePointAt(i);
            i += Character.charCount(c);

            switch (c) {

                case '&':
                    toWrite = _AMP_;
                    break;

                case '<':
                    toWrite = _LT_;
                    break;

                case '"':
                    toWrite = _QUOT_;
                    break;

                case 0x09:    // '\t'
                    toWrite = __X9_;
                    break;

                case 0x0A:    // '\n'
                    toWrite = __XA_;
                    break;

                case 0x0D:    // '\r'
                    toWrite = __XD_;
                    break;

                default:
                    if (c < 0x80) {
                        writer.write(c);
                    } else {
                        UtfHelpper.writeCodePointToUtf8(c, writer);
                    }
                    continue;
            }
            writer.write(toWrite);
        }

        writer.write('\"');
    }

    /**
     * Outputs a Text of CDATA section to the internal Writer.
     *
     * @param text
     * @param writer writer where to write the things
     * @throws IOException
     */
    protected static void outputTextToWriter(final String text, final OutputStream writer) throws IOException {
        final int length = text.length();
        byte[] toWrite;
        for (int i = 0; i < length; ) {
            final int c = text.codePointAt(i);
            i += Character.charCount(c);

            switch (c) {

                case '&':
                    toWrite = _AMP_;
                    break;

                case '<':
                    toWrite = _LT_;
                    break;

                case '>':
                    toWrite = _GT_;
                    break;

                case 0xD:
                    toWrite = __XD_;
                    break;

                default:
                    if (c < 0x80) {
                        writer.write(c);
                    } else {
                        UtfHelpper.writeCodePointToUtf8(c, writer);
                    }
                    continue;
            }
            writer.write(toWrite);
        }
    }

    protected static void outputTextToWriter(final char[] text, final OutputStream writer) throws IOException {
        final int length = text.length;
        byte[] toWrite;
        for (int i = 0; i < length; i++) {
            int c;
            if (Character.isHighSurrogate(text[i]) && i + 1 != length && Character.isLowSurrogate(text[i+1])) {
                c = Character.toCodePoint(text[i], text[++i]);
            } else {
                c = text[i];
            }

            switch (c) {

                case '&':
                    toWrite = _AMP_;
                    break;

                case '<':
                    toWrite = _LT_;
                    break;

                case '>':
                    toWrite = _GT_;
                    break;

                case 0xD:
                    toWrite = __XD_;
                    break;

                default:
                    if (c < 0x80) {
                        writer.write(c);
                    } else {
                        UtfHelpper.writeCodePointToUtf8(c, writer);
                    }
                    continue;
            }
            writer.write(toWrite);
        }
    }

    /**
     * Outputs a PI to the internal Writer.
     *
     * @param currentPI
     * @param writer    where to write the things
     * @throws IOException
     */
    protected static void outputPItoWriter(XMLSecProcessingInstruction currentPI, OutputStream writer, DocumentLevel position) throws IOException {
        if (position == DocumentLevel.NODE_AFTER_DOCUMENT_ELEMENT) {
            writer.write(NEWLINE);
        }
        writer.write(_BEGIN_PI);

        final String target = currentPI.getTarget();
        int length = target.length();

        for (int i = 0; i < length; ) {
            final int c = target.codePointAt(i);
            i += Character.charCount(c);
            if (c == 0x0D) {
                writer.write(__XD_);
            } else {
                if (c < 0x80) {
                    writer.write(c);
                } else {
                    UtfHelpper.writeCodePointToUtf8(c, writer);
                }
            }
        }

        final String data = currentPI.getData();

        length = data.length();

        if (length > 0) {
            writer.write(' ');

            for (int i = 0; i < length; ) {
                int c = data.codePointAt(i);
                i += Character.charCount(c);
                if (c == 0x0D) {
                    writer.write(__XD_);
                } else {
                    UtfHelpper.writeCodePointToUtf8(c, writer);
                }
            }
        }

        writer.write(_END_PI);
        if (position == DocumentLevel.NODE_BEFORE_DOCUMENT_ELEMENT) {
            writer.write(NEWLINE);
        }
    }

    /**
     * Method outputCommentToWriter
     *
     * @param currentComment
     * @param writer         writer where to write the things
     * @throws IOException
     */
    protected static void outputCommentToWriter(XMLSecComment currentComment, OutputStream writer, DocumentLevel position) throws IOException {
        if (position == DocumentLevel.NODE_AFTER_DOCUMENT_ELEMENT) {
            writer.write(NEWLINE);
        }
        writer.write(_BEGIN_COMM);

        final String data = currentComment.getText();
        final int length = data.length();

        for (int i = 0; i < length; ) {
            final int c = data.codePointAt(i);
            i += Character.charCount(c);
            if (c == 0x0D) {
                writer.write(__XD_);
            } else {
                if (c < 0x80) {
                    writer.write(c);
                } else {
                    UtfHelpper.writeCodePointToUtf8(c, writer);
                }
            }
        }

        writer.write(_END_COMM);
        if (position == DocumentLevel.NODE_BEFORE_DOCUMENT_ELEMENT) {
            writer.write(NEWLINE);
        }
    }

    private boolean namespaceIsAbsolute(final String namespaceValue) {
        // assume empty namespaces are absolute
        if (namespaceValue.isEmpty()) {
            return true;
        }
        return namespaceValue.indexOf(DOUBLEPOINT) > 0;
    }


    public static class C14NStack<E> extends ArrayDeque<List<Comparable>> {

        public Object containsOnStack(final Object o) {
            //Important: iteration order from head to tail!
            final Iterator<List<Comparable>> elementIterator = super.iterator();
            while (elementIterator.hasNext()) {
                final List list = elementIterator.next();
                if (list.isEmpty()) {
                    continue;
                }
                final int idx = list.lastIndexOf(o);
                if (idx != -1) {
                    return list.get(idx);
                }
            }
            return null;
        }

        @Override
        public List<Comparable> peek() {
            List<Comparable> list = super.peekFirst();
            if (list == Collections.<Comparable>emptyList()) {
                super.removeFirst();
                list = new ArrayList<>();
                super.addFirst(list);
            }
            return list;
        }

        @Override
        public List<Comparable> peekFirst() {
            throw new UnsupportedOperationException("Use peek()");
        }
    }
}
