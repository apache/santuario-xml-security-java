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

import java.io.IOException;
import java.io.Writer;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;

import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecNamespace;

/**
 * Class to let XML-Attributes be comparable how it is requested by C14N
 *
 */
public class XMLSecAttributeImpl extends XMLSecEventBaseImpl implements XMLSecAttribute {

    private final QName name;
    private final String value;
    private XMLSecNamespace attributeNamespace;

    public XMLSecAttributeImpl(QName name, String value) {
        this.name = name;
        this.value = value;
    }

    @Override
    public int compareTo(XMLSecAttribute o) {
        //An element's attribute nodes are sorted lexicographically with namespace URI as the primary
        //key and local name as the secondary key (an empty namespace URI is lexicographically least).
        int namespacePartCompare = this.name.getNamespaceURI().compareTo(o.getName().getNamespaceURI());
        if (namespacePartCompare != 0) {
            return namespacePartCompare;
        } else {
            return this.name.getLocalPart().compareTo(o.getName().getLocalPart());
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof XMLSecAttribute)) {
            return false;
        }
        XMLSecAttribute comparableAttribute = (XMLSecAttribute) obj;
        if (comparableAttribute.hashCode() != this.hashCode()) {
            return false;
        }
        return comparableAttribute.getName().getLocalPart().equals(this.name.getLocalPart());
    }

    @Override
    public int hashCode() {
        //we don't have to cache the hashCode. The string class takes already care of it.
        return this.name.getLocalPart().hashCode();
    }

    @Override
    public XMLSecNamespace getAttributeNamespace() {
        if (this.attributeNamespace == null) {
            this.attributeNamespace = XMLSecNamespaceImpl.getInstance(this.name.getPrefix(), this.name.getNamespaceURI());
        }
        return this.attributeNamespace;
    }

    @Override
    public QName getName() {
        return name;
    }

    @Override
    public String getValue() {
        return value;
    }

    @Override
    public String getDTDType() {
        return "CDATA";
    }

    @Override
    public boolean isSpecified() {
        return true;
    }

    @Override
    public int getEventType() {
        return XMLStreamConstants.ATTRIBUTE;
    }

    @Override
    public boolean isAttribute() {
        return true;
    }

    @Override
    public void writeAsEncodedUnicode(Writer writer) throws XMLStreamException {
        try {
            final String prefix = getName().getPrefix();
            if (prefix != null && !prefix.isEmpty()) {
                writer.write(prefix);
                writer.write(':');
            }
            writer.write(getName().getLocalPart());
            writer.write("=\"");
            writeEncoded(writer, getValue());
            writer.write("\"");
        } catch (IOException e) {
            throw new XMLStreamException(e);
        }
    }

    private void writeEncoded(Writer writer, String text) throws IOException {
        final int length = text.length();

        int i = 0;
        int idx = 0;
        while (i < length) {
            char c = text.charAt(i);
            if (c == '&') {
                writer.write(text, idx, i - idx);
                writer.write("&amp;");
                idx = i + 1;
            } else if (c == '"') {
                writer.write(text, idx, i - idx);
                writer.write("&quot;");
                idx = i + 1;
            }
            i++;
        }
        writer.write(text, idx, length - idx);
    }
}
