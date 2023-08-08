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


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Base64;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.signature.XMLSignatureByteInput;
import org.apache.xml.security.signature.XMLSignatureDigestInput;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.signature.XMLSignatureInputDebugger;
import org.junit.jupiter.api.Test;

import static java.nio.charset.StandardCharsets.UTF_8;
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
class XMLSignatureInputTest {

    private static final String _octetStreamTextInput = "Kleiner Test";
    static {
        org.apache.xml.security.Init.init();
    }

    @Test
    void testSetOctetStreamGetOctetStream()
        throws IOException, CanonicalizationException, InvalidCanonicalizerException {
        XMLSignatureByteInput input = new XMLSignatureByteInput(_octetStreamTextInput.getBytes(UTF_8));
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // NOPMD: Test checks that input has same content as getter
        InputStream res = input.getUnprocessedInput(); // NOPMD
        int off = 0;
        while (res.available() > 0) {
            byte[] array = new byte[1024];
            int len = res.read(array);
            baos.write(array, off, len);
            off += len;
        }

        byte[] resBytes = baos.toByteArray();
        String resString = new String(resBytes, UTF_8);

        assertEquals(resString, _octetStreamTextInput);
    }

    @Test
    void testIsInitializedWithOctetStream() throws IOException {
        XMLSignatureInput input = new XMLSignatureByteInput(_octetStreamTextInput.getBytes(UTF_8));
        assertTrue(input.hasUnprocessedInput(), "hasUnprocessedInput");
        assertFalse(input.isNodeSet(), "isNodeSet");
    }

    @Test
    void testOctetStreamIsOctetStream() throws IOException {
        XMLSignatureInput input = new XMLSignatureByteInput( _octetStreamTextInput.getBytes(UTF_8));
        assertTrue(input.hasUnprocessedInput(), "hasUnprocessedInput");
        assertFalse(input.isNodeSet(), "isNodeSet");
    }

    @Test
    void testOctetStreamIsNotNodeSet() throws IOException {
        XMLSignatureInput input = new XMLSignatureByteInput( _octetStreamTextInput.getBytes(UTF_8));
        assertTrue(input.hasUnprocessedInput(), "hasUnprocessedInput");
        assertFalse(input.isNodeSet(), "isNodeSet");
    }

    @Test
    void testToString() throws IOException {
        XMLSignatureInput input = new XMLSignatureByteInput( _octetStreamTextInput.getBytes(UTF_8));
        assertTrue(input.hasUnprocessedInput(), "hasUnprocessedInput");
        assertFalse(input.isNodeSet(), "isNodeSet");
        assertTrue(input.toString().startsWith("XMLSignatureByteInput"));
    }

    @Test
    void testHTMLRepresentation() throws IOException, XMLSignatureException {
        XMLSignatureInput input = new XMLSignatureByteInput( _octetStreamTextInput.getBytes(UTF_8));
        assertTrue(input.hasUnprocessedInput(), "hasUnprocessedInput");
        assertFalse(input.isNodeSet(), "isNodeSet");
        assertNotNull(new XMLSignatureInputDebugger(input).getHTMLRepresentation());
    }

    @Test
    void test() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest("Hello world!".getBytes());
        XMLSignatureInput input = new XMLSignatureDigestInput(Base64.getEncoder().encodeToString(digest));
        assertNull(input.getBytes());
    }
}
