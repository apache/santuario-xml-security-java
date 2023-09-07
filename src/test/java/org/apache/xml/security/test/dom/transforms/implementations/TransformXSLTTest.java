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
package org.apache.xml.security.test.dom.transforms.implementations;

import java.io.File;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.signature.XMLSignatureNodeInput;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;

class TransformXSLTTest {

    private static final String SOURCE_PATH = "src/test/resources/com/phaos/phaos-xmldsig-three";
    private static final String SIGNATURE_FILE = "signature-rsa-detached-xslt-transform.xml";
    private static final String STYLESHEET_FILE = "document-stylesheet.xml";

    static {
        org.apache.xml.security.Init.init();
    }

    /**
     * Make sure Transform.performTransform does not throw NullPointerException.
     * See bug 41927 for more info.
     */
    @Test
    void test1() throws Exception {
        Document doc1 = getDocument(SIGNATURE_FILE);
        Document doc2 = getDocument(STYLESHEET_FILE);

        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());

        String expression = "//ds:Transform[1]";
        Element transformEl = (Element) xpath.evaluate(expression, doc1, XPathConstants.NODE);

        Transform transform = new Transform(doc1, Transforms.TRANSFORM_XSLT, transformEl.getChildNodes());
        transform.performTransform(new XMLSignatureNodeInput(doc2), false);
    }

    private static Document getDocument(String fileName) throws Exception {
        return XMLUtils.read(new File(resolveFile(SOURCE_PATH), fileName), false);
    }

}
