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
package org.apache.xml.security.test.dom.signature;

import java.net.URL;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.Init;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.junit.Assert.assertNotNull;

/**
 * A test for SANTUARIO-499 - https://issues.apache.org/jira/browse/SANTUARIO-499
 * TransformXSLT doesn't support xslt:transform synonym
 */
public class Santuario499Test {

    static org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(Santuario499Test.class);

    static {
        Init.init();
    }

    @org.junit.Test
    public void testXSLTTransform() throws Exception {

        URL signatureFile = this.getClass().getResource("Arbeidstijd_anonymous.xml");
        assertNotNull(signatureFile);

        Document doc = XMLUtils.createDocumentBuilder(false).parse(signatureFile.openStream());

        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());

        String expression = "//ds:Signature[1]";
        Element sigElement =
            (Element) xpath.evaluate(expression, doc, XPathConstants.NODE);

        NodeList mainNode = doc.getElementsByTagName("Arbeidstijden");
        Element ritAdministratieElement = (Element) mainNode.item(0);
        ritAdministratieElement.setIdAttributeNS(null, "Id", true);

        XMLSignature signature = new XMLSignature(sigElement, "", false);
        // Note that the Signature is not valid so we won't check that
        signature.checkSignatureValue(signature.getKeyInfo().getPublicKey());
    }

}