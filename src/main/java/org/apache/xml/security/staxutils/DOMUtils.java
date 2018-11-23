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

package org.apache.xml.security.staxutils;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

/**
 * Few simple utils to read DOM. This is originally from the Jakarta Commons Modeler.
 */
public final class DOMUtils {
    private static final Map<ClassLoader, DocumentBuilder> DOCUMENT_BUILDERS
        = Collections.synchronizedMap(new WeakHashMap<ClassLoader, DocumentBuilder>());
    private static final Map<ClassLoader, DocumentBuilder> DOCUMENT_BUILDERS_DISALLOW_DOCTYPE
        = Collections.synchronizedMap(new WeakHashMap<ClassLoader, DocumentBuilder>());

    private DOMUtils() {
    }

    private static DocumentBuilder getDocumentBuilder(boolean disAllowDocTypeDeclarations) throws ParserConfigurationException {
        ClassLoader loader = getContextClassLoader();
        if (loader == null) {
            loader = getClassLoader(DOMUtils.class);
        }
        if (loader == null) {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setNamespaceAware(true);
            f.setFeature(javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING, true);
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", disAllowDocTypeDeclarations);
            return f.newDocumentBuilder();
        }
        DocumentBuilder factory =
            disAllowDocTypeDeclarations ? DOCUMENT_BUILDERS_DISALLOW_DOCTYPE.get(loader) : DOCUMENT_BUILDERS.get(loader);
        if (factory == null) {
            DocumentBuilderFactory f2 = DocumentBuilderFactory.newInstance();
            f2.setNamespaceAware(true);
            f2.setFeature(javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING, true);
            f2.setFeature("http://apache.org/xml/features/disallow-doctype-decl", disAllowDocTypeDeclarations);
            factory = f2.newDocumentBuilder();
            if (disAllowDocTypeDeclarations) {
                DOCUMENT_BUILDERS_DISALLOW_DOCTYPE.put(loader, factory);
            } else {
                DOCUMENT_BUILDERS.put(loader, factory);
            }
        }
        return factory;
    }

    private static ClassLoader getContextClassLoader() {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            return AccessController.doPrivileged(new PrivilegedAction<ClassLoader>() {
                public ClassLoader run() {
                    return Thread.currentThread().getContextClassLoader();
                }
            });
        }
        return Thread.currentThread().getContextClassLoader();
    }

    private static ClassLoader getClassLoader(final Class<?> clazz) {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            return AccessController.doPrivileged(new PrivilegedAction<ClassLoader>() {
                public ClassLoader run() {
                    return clazz.getClassLoader();
                }
            });
        }
        return clazz.getClassLoader();
    }

    /**
     * Creates a new Document object
     * @throws ParserConfigurationException
     */
    public static Document newDocument(boolean disAllowDocTypeDeclarations) {
        try {
            return getDocumentBuilder(disAllowDocTypeDeclarations).newDocument();
        } catch (ParserConfigurationException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Get the raw text content of a node or null if there is no text
     */
    public static String getRawContent(Node n) {
        if (n == null) {
            return null;
        }
        StringBuilder b = null;
        String s = null;
        Node n1 = n.getFirstChild();
        while (n1 != null) {
            if (n1.getNodeType() == Node.TEXT_NODE || n1.getNodeType() == Node.CDATA_SECTION_NODE) {
                if (b != null) {
                    b.append(((Text)n1).getNodeValue());
                } else if (s == null) {
                    s = ((Text)n1).getNodeValue();
                } else {
                    b = new StringBuilder(s).append(((Text)n1).getNodeValue());
                    s = null;
                }
            }
            n1 = n1.getNextSibling();
        }
        if (b != null) {
            return b.toString();
        }
        return s;
    }

}
