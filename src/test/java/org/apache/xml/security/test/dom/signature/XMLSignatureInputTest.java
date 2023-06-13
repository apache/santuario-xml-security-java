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


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Base64;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit test for {@link org.apache.xml.security.signature.XMLSignatureInput}
 *
 * @see <A HREF="http://nagoya.apache.org/bugzilla/show_bug.cgi?id=4336">Bug 4336</A>
 */
public class XMLSignatureInputTest {

    static final String _octetStreamTextInput = "Kleiner Test";
    static final String _nodeSetInput1 =
        "<?xml version=\"1.0\"?>\n"
        + "<!DOCTYPE doc [\n"
        + "<!ELEMENT doc (n+)>\n"
        + "<!ELEMENT n (#PCDATA)>\n"
        + "]>\n"
        + "<!-- full document with decl -->"
        + "<doc>"
        + "<n>1</n>"
        + "<n>2</n>"
        + "<n>3</n>"
        + "<n>4</n>"
        + "</doc>";
    // added one for xmlns:xml since Xalan 2.2.D11
    static final int _nodeSetInput1Nodes = 11; // was 10
    static final int _nodeSetInput1NodesWithComments = _nodeSetInput1Nodes + 1;
    static final String _nodeSetInput2 =
        "<?xml version=\"1.0\"?>\n"
        + "<!-- full document -->"
        + "<doc>"
        + "<n>1</n>"
        + "<n>2</n>"
        + "<n>3</n>"
        + "<n>4</n>"
        + "</doc>";
    // added one for xmlns:xml since Xalan 2.2.D11
    static final int _nodeSetInput2Nodes = 11; // was 10
    static final int _nodeSetInput2NodesWithComments = _nodeSetInput2Nodes + 1;
    static final String _nodeSetInput3 =
        "<!-- document -->"
        + "<doc>"
        + "<n>1</n>"
        + "<n>2</n>"
        + "<n>3</n>"
        + "<n>4</n>"
        + "</doc>";
    // added one for xmlns:xml since Xalan 2.2.D11
    static final int _nodeSetInput3Nodes = 11; // was 10
    static final int _nodeSetInput3NodesWithComments = _nodeSetInput3Nodes + 1;

    static {
        org.apache.xml.security.Init.init();
    }

    @Test
    public void testSetOctetStreamGetOctetStream()
        throws IOException, CanonicalizationException, InvalidCanonicalizerException {
        InputStream inputStream =
            new ByteArrayInputStream(_octetStreamTextInput.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        XMLSignatureInput input = new XMLSignatureInput(inputStream);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        InputStream res = input.getOctetStream();
        int off = 0;

        while (res.available() > 0) {
            byte[] array = new byte[1024];
            int len = res.read(array);

            baos.write(array, off, len);
            off += len;
        }

        byte[] resBytes = baos.toByteArray();
        String resString = new String(resBytes, java.nio.charset.StandardCharsets.UTF_8);

        assertEquals(resString, _octetStreamTextInput);
    }

    @Test
    public void testIsInitializedWithOctetStream() throws IOException {
        try (InputStream inputStream =
            new ByteArrayInputStream(_octetStreamTextInput.getBytes())) {
            XMLSignatureInput input = new XMLSignatureInput(inputStream);

            assertTrue(input.isInitialized(), "Input is initialized");
        }
    }

    @Test
    public void testOctetStreamIsOctetStream() throws IOException {
        try (InputStream inputStream =
            new ByteArrayInputStream(_octetStreamTextInput.getBytes())) {
            XMLSignatureInput input = new XMLSignatureInput(inputStream);

            assertTrue(input.isOctetStream(), "Input is octet stream");
        }
    }

    @Test
    public void testOctetStreamIsNotNodeSet() throws IOException {
        try (InputStream inputStream =
            new ByteArrayInputStream(_octetStreamTextInput.getBytes())) {
            XMLSignatureInput input = new XMLSignatureInput(inputStream);

            assertFalse(input.isNodeSet(), "Input is not node set");
        }
    }

    @Test
    public void testToString() throws IOException {
        try (InputStream inputStream =
                     new ByteArrayInputStream(_octetStreamTextInput.getBytes())) {
            XMLSignatureInput input = new XMLSignatureInput(inputStream);

            assertTrue(input.isInitialized(), "Input is initialized");
            assertTrue(input.toString().startsWith("XMLSignatureInput"));
        }
    }

    @Test
    public void testHTMLRepresentation() throws IOException, XMLSignatureException {
        try (InputStream inputStream =
                     new ByteArrayInputStream(_octetStreamTextInput.getBytes())) {
            XMLSignatureInput input = new XMLSignatureInput(inputStream);

            assertTrue(input.isInitialized(), "Input is initialized");
            assertNotNull(input.getHTMLRepresentation());
        }
    }

    @Test
    public void test() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest("Hello world!".getBytes());
        XMLSignatureInput input = new XMLSignatureInput(Base64.getEncoder().encodeToString(digest));
        assertNull(input.getBytes());
    }
}
