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

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class TestUtils {

    private static final DocumentBuilderFactory DBF = DocumentBuilderFactory.newInstance();
    private static final boolean isJava11Compatible;

    static {
        DBF.setNamespaceAware(true);
        try {
            DBF.setFeature(javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING, true);
        } catch (ParserConfigurationException e) {
            // Ignore: DocumentBuilderFactory is required to support the secure processing feature
            e.printStackTrace();        // NOPMD
        }

        String version = System.getProperty("java.version");
        if (version.indexOf('.') > 0) {
            version = version.substring(0, version.indexOf('.'));
        }
        if (version.indexOf('-') > 0) {
            version = version.substring(0, version.indexOf('-'));
        }

        isJava11Compatible = Integer.valueOf(version) >= 11;
    }

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

    public static Document newDocument() throws ParserConfigurationException {
        return DBF.newDocumentBuilder().newDocument();
    }

    public static boolean isJava11Compatible() {
        return isJava11Compatible;
    }
}
