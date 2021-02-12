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

import org.apache.xml.security.stax.ext.stax.XMLSecCharacters;
import org.apache.xml.security.stax.ext.stax.XMLSecEndElement;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;

import javax.xml.namespace.QName;
import javax.xml.stream.Location;
import javax.xml.stream.XMLStreamException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

/**
 */
public abstract class XMLSecEventBaseImpl implements XMLSecEvent {

    private static final EmptyIterator EMPTY_ITERATOR = new EmptyIterator();
    protected XMLSecStartElement parentXMLSecStartElement;

    @SuppressWarnings("unchecked")
    protected static <T> EmptyIterator<T> getEmptyIterator() {
        return (EmptyIterator<T>)EMPTY_ITERATOR;
    }

    @Override
    public void setParentXMLSecStartElement(XMLSecStartElement xmlSecStartElement) {
        this.parentXMLSecStartElement = xmlSecStartElement;
    }

    @Override
    public XMLSecStartElement getParentXMLSecStartElement() {
        return parentXMLSecStartElement;
    }

    @Override
    public int getDocumentLevel() {
        if (parentXMLSecStartElement != null) {
            return parentXMLSecStartElement.getDocumentLevel();
        }
        return 0;
    }

    @Override
    public void getElementPath(List<QName> list) {
        if (parentXMLSecStartElement != null) {
            parentXMLSecStartElement.getElementPath(list);
        }
    }

    @Override
    public List<QName> getElementPath() {
        final List<QName> elementPath = new ArrayList<>();
        getElementPath(elementPath);
        return elementPath;
    }

    @Override
    public XMLSecStartElement getStartElementAtLevel(int level) {
        if (getDocumentLevel() < level) {
            return null;
        }
        return parentXMLSecStartElement.getStartElementAtLevel(level);
    }

    @Override
    public Location getLocation() {
        return new LocationImpl();
    }

    @Override
    public boolean isStartElement() {
        return false;
    }

    @Override
    public boolean isAttribute() {
        return false;
    }

    @Override
    public boolean isNamespace() {
        return false;
    }

    @Override
    public boolean isEndElement() {
        return false;
    }

    @Override
    public boolean isEntityReference() {
        return false;
    }

    @Override
    public boolean isProcessingInstruction() {
        return false;
    }

    @Override
    public boolean isCharacters() {
        return false;
    }

    @Override
    public boolean isStartDocument() {
        return false;
    }

    @Override
    public boolean isEndDocument() {
        return false;
    }

    @Override
    public XMLSecStartElement asStartElement() {
        throw new ClassCastException();
    }

    @Override
    public XMLSecEndElement asEndElement() {
        throw new ClassCastException();
    }

    @Override
    public XMLSecCharacters asCharacters() {
        throw new ClassCastException();
    }

    @Override
    public QName getSchemaType() {
        return null;
    }

    @Override
    public void writeAsEncodedUnicode(Writer writer) throws XMLStreamException {
        throw new UnsupportedOperationException(
                "writeAsEncodedUnicode not implemented for " + this.getClass().getName());
    }

    static final class LocationImpl implements Location {

        @Override
        public int getLineNumber() {
            return 0;
        }

        @Override
        public int getColumnNumber() {
            return 0;
        }

        @Override
        public int getCharacterOffset() {
            return 0;
        }

        @Override
        public String getPublicId() {
            return null;
        }

        @Override
        public String getSystemId() {
            return null;
        }
    }

    private static final class EmptyIterator<E> implements Iterator<E> {
        @Override
        public boolean hasNext() {
            return false;
        }

        @Override
        public E next() {
            throw new NoSuchElementException();
        }

        @Override
        public void remove() {
            throw new IllegalStateException();
        }
    }
}
