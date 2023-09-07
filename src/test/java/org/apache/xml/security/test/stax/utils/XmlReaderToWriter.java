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

import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;

public final class XmlReaderToWriter {

    private XmlReaderToWriter() {
    }


    /**
     * Writes everything from the reader to the writer, then closes both reader and writer.
     *
     * @param reader
     * @param writer
     * @throws XMLStreamException
     */
    public static void writeAllAndClose(XMLStreamReader reader, XMLStreamWriter writer) throws XMLStreamException {
        try {
            try {
                writeAll(reader, writer);
            } finally {
                reader.close();
            }
        } finally {
            writer.close();
        }
    }


    /**
     * Writes everything from the reader to the writer. Doesn't close the input.
     *
     * @param reader
     * @param writer
     * @throws XMLStreamException
     */
    public static void writeAll(XMLStreamReader reader, XMLStreamWriter writer)
            throws XMLStreamException {
        // Some implementations, Woodstox for example, already position their reader ON the first event, which is.
        // typically a START_DOCUMENT event.
        // If already positioned on an event, that is indicated by the event type.
        // Make sure we don't miss the initial event.
        if (reader.getEventType() > 0) {
            write(reader, writer);
        }
        while (reader.hasNext()) {
            reader.next();
            write(reader, writer);
        }
        //write(xmlr, writer); // write the last element
        writer.flush();
    }

    public static void write(XMLStreamReader reader, XMLStreamWriter writer) throws XMLStreamException {
        switch (reader.getEventType()) {
            case XMLStreamConstants.START_ELEMENT:
                final String localName = reader.getLocalName();
                final String namespaceURI = reader.getNamespaceURI();
                if (namespaceURI != null && namespaceURI.length() > 0) {
                    final String prefix = reader.getPrefix();
                    if (prefix != null) {
                        writer.writeStartElement(prefix, localName, namespaceURI);
                    } else {
                        writer.writeStartElement(namespaceURI, localName);
                    }
                } else {
                    writer.writeStartElement(localName);
                }

                for (int i = 0, len = reader.getNamespaceCount(); i < len; i++) {
                    String prefix = reader.getNamespacePrefix(i);
                    if (prefix == null) {
                        writer.writeDefaultNamespace(reader.getNamespaceURI(i));
                    } else {
                        writer.writeNamespace(prefix, reader.getNamespaceURI(i));
                    }
                }

                for (int i = 0, len = reader.getAttributeCount(); i < len; i++) {
                    final String attUri = reader.getAttributeNamespace(i);

                    if (attUri != null && attUri.length() > 0) {
                        final String prefix = reader.getAttributePrefix(i);
                        if (prefix != null) {
                            writer.writeAttribute(prefix, attUri, reader.getAttributeLocalName(i), reader.getAttributeValue(i));
                        } else {
                            writer.writeAttribute(attUri, reader.getAttributeLocalName(i), reader.getAttributeValue(i));
                        }
                    } else {
                        writer.writeAttribute(reader.getAttributeLocalName(i), reader.getAttributeValue(i));
                    }

                }
                break;
            case XMLStreamConstants.END_ELEMENT:
                writer.writeEndElement();
                break;
            case XMLStreamConstants.SPACE:
            case XMLStreamConstants.CHARACTERS:
                char[] text = new char[reader.getTextLength()];
                reader.getTextCharacters(0, text, 0, reader.getTextLength());
                writer.writeCharacters(text, 0, text.length);
                break;
            case XMLStreamConstants.PROCESSING_INSTRUCTION:
                writer.writeProcessingInstruction(reader.getPITarget(), reader.getPIData());
                break;
            case XMLStreamConstants.CDATA:
                writer.writeCData(reader.getText());
                break;
            case XMLStreamConstants.COMMENT:
                writer.writeComment(reader.getText());
                break;
            case XMLStreamConstants.ENTITY_REFERENCE:
                writer.writeEntityRef(reader.getLocalName());
                break;
            case XMLStreamConstants.START_DOCUMENT:
                String encoding = reader.getCharacterEncodingScheme();
                String version = reader.getVersion();

                if (encoding != null && version != null) {
                    writer.writeStartDocument(encoding, version);
                } else if (version != null) {
                    writer.writeStartDocument(reader.getVersion());
                }
                break;
            case XMLStreamConstants.END_DOCUMENT:
                writer.writeEndDocument();
                break;
            case XMLStreamConstants.DTD:
                writer.writeDTD(reader.getText());
                break;
        }
    }
}
