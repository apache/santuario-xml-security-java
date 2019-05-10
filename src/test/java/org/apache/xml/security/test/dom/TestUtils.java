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
package org.apache.xml.security.test.dom;

import java.io.FileInputStream;
import java.io.IOException;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.apache.xml.security.staxutils.DOMUtils;
import org.apache.xml.security.staxutils.StaxUtils;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

public class TestUtils {

    /**
     * Method createDSctx
     *
     * @param doc
     * @param prefix
     * @param namespace
     * @return the element.
     */
    public static Element createDSctx(Document doc, String prefix, String namespace) {
        if (prefix == null || prefix.trim().length() == 0) {
            throw new IllegalArgumentException("You must supply a prefix");
        }

        Element ctx = doc.createElementNS(null, "namespaceContext");
        ctx.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:" + prefix.trim(), namespace);
        return ctx;
    }

    public static Document read(String uri, String systemId, boolean disAllowDocTypeDeclarations)
        throws ParserConfigurationException, SAXException, IOException, XMLStreamException {
        XMLStreamReader reader = StaxUtils.createXMLStreamReader(systemId, new FileInputStream(uri), disAllowDocTypeDeclarations);
        try {
            Document doc = DOMUtils.newDocument(disAllowDocTypeDeclarations);
            if (reader.getLocation().getSystemId() != null) {
                try {
                    doc.setDocumentURI(reader.getLocation().getSystemId());
                } catch (Exception e) {
                    //ignore - probably not DOM level 3
                }
            }
            StaxUtils.readDocElements(doc, doc, reader, true, false);
            return doc;
        } finally {
            try {
                reader.close();
            } catch (Exception ex) {
                //ignore
            }
        }
    }

}
