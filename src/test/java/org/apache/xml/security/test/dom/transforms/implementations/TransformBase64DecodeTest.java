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


import java.io.ByteArrayInputStream;
import java.io.InputStream;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Unit test for {@link org.apache.xml.security.transforms.implementations.TransformBase64Decode}
 *
 */
public class TransformBase64DecodeTest {

    static org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(TransformBase64DecodeTest.class);

    static {
        org.apache.xml.security.Init.init();
    }

    @Test
    public void test1() throws Exception {
        // base64 encoded
        final String s1 =
            "VGhlIFVSSSBvZiB0aGUgdHJhbnNmb3JtIGlzIGh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1s\n"
            + "ZHNpZyNiYXNlNjQ=";

        final Document doc = TransformBase64DecodeTest.createDocument();
        final Transforms t = new Transforms(doc);
        doc.appendChild(t.getElement());
        t.addTransform(Transforms.TRANSFORM_BASE64_DECODE);

        XMLSignatureInput in = null;
        try (InputStream is = new ByteArrayInputStream(s1.getBytes())) {
            in = new XMLSignatureInput(is);
        }
        final XMLSignatureInput out = t.performTransforms(in);
        final String result = new String(out.getBytes());

        assertEquals(result, "The URI of the transform is http://www.w3.org/2000/09/xmldsig#base64");
    }

    @Test
    public void test2() throws Exception {
        // base64 encoded twice
        final String s2 =
            "VkdobElGVlNTU0J2WmlCMGFHVWdkSEpoYm5ObWIzSnRJR2x6SUdoMGRIQTZMeTkzZDNjdWR6TXVi\n"
            + "M0puTHpJd01EQXZNRGt2ZUcxcwpaSE5wWnlOaVlYTmxOalE9";
        final Document doc = TransformBase64DecodeTest.createDocument();
        final Transforms t = new Transforms(doc);
        doc.appendChild(t.getElement());

        t.addTransform(Transforms.TRANSFORM_BASE64_DECODE);

        XMLSignatureInput in = null;
        try (InputStream is = new ByteArrayInputStream(s2.getBytes())) {
            in = new XMLSignatureInput(is);
        }
        final XMLSignatureInput out = t.performTransforms(t.performTransforms(in));
        final String result = new String(out.getBytes());

        assertEquals(result, "The URI of the transform is http://www.w3.org/2000/09/xmldsig#base64");
    }

    @Test
    public void test3() throws Exception {
        //J-
        final String input = ""
            + "<Object xmlns:signature='http://www.w3.org/2000/09/xmldsig#'>\n"
            + "<signature:Base64>\n"
            + "VGhlIFVSSSBvZiB0aGU gdHJhbn<RealText>Nmb  3JtIGlzIG<test/>h0dHA6</RealText>Ly93d3cudzMub3JnLzIwMDAvMDkveG1s\n"
            + "ZHNpZyNiYXNlNjQ=\n"
            + "</signature:Base64>\n"
            + "</Object>\n"
            ;
        //J+

        Document doc = null;
        try (InputStream is = new ByteArrayInputStream(input.getBytes())) {
            doc = XMLUtils.read(is, false);
        }
        //XMLUtils.circumventBug2650(doc);

        final XPathFactory xpf = XPathFactory.newInstance();
        final XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());

        final String expression = "//ds:Base64";
        final Node base64Node =
            (Node) xpath.evaluate(expression, doc, XPathConstants.NODE);

        final XMLSignatureInput xmlinput = new XMLSignatureInput(base64Node);

        final Document doc2 = TransformBase64DecodeTest.createDocument();
        final Transforms t = new Transforms(doc2);
        doc2.appendChild(t.getElement());
        t.addTransform(Transforms.TRANSFORM_BASE64_DECODE);

        final XMLSignatureInput out = t.performTransforms(xmlinput);
        final String result = new String(out.getBytes());

        assertEquals(
            result, "The URI of the transform is http://www.w3.org/2000/09/xmldsig#base64",
            "\"" + result + "\""
        );
    }

    private static Document createDocument() throws ParserConfigurationException {
        final Document doc = TestUtils.newDocument();

        if (doc == null) {
            throw new RuntimeException("Could not create a Document");
        } else {
            LOG.debug("I could create the Document");
        }
        return doc;
    }

}