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

import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;

import org.apache.xml.security.stax.ext.stax.XMLSecEntityDeclaration;

/**
 */
public class XMLSecEntityDeclarationImpl extends XMLSecEventBaseImpl implements XMLSecEntityDeclaration {

    public XMLSecEntityDeclarationImpl(String name) {
        this.name = name;
    }

    private String name;

    @Override
    public String getPublicId() {
        return null;
    }

    @Override
    public String getSystemId() {
        return null;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getNotationName() {
        return null;
    }

    @Override
    public String getReplacementText() {
        return null;
    }

    @Override
    public String getBaseURI() {
        return null;
    }

    @Override
    public int getEventType() {
        return XMLStreamConstants.ENTITY_DECLARATION;
    }

    @Override
    public boolean isEntityReference() {
        return true;
    }

    @Override
    public void writeAsEncodedUnicode(Writer writer) throws XMLStreamException {
        try {
            writer.write("<!ENTITY ");
            writer.write(getName());
            writer.write(" \"");
            final String replacementText = getReplacementText();
            if (replacementText != null) {
                writer.write(replacementText);
            }
            writer.write("\">");
        } catch (IOException e) {
            throw new XMLStreamException(e);
        }
    }
}
