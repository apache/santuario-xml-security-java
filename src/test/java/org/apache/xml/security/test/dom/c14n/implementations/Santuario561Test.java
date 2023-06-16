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
package org.apache.xml.security.test.dom.c14n.implementations;

import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.Base64;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.signature.XMLSignatureDigestInput;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.implementations.TransformC14N;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * This is a test for Santuario-561:
 *
 * https://issues.apache.org/jira/browse/SANTUARIO-561
 *
 * TransformC14N returns empty byte array when nothing is provided as an input
 */
class Santuario561Test {

    @Test
    void transformC14NWithDigestTest() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest("Hello world!".getBytes());
        XMLSignatureInput inputPrecomputed = new XMLSignatureDigestInput(Base64.getEncoder().encodeToString(digest));

        MockTransformC14N mockTransformC14N = new MockTransformC14N();

        XMLSignatureInput xmlSignatureOutput =
                mockTransformC14N.enginePerformTransform(inputPrecomputed, null, null, null, false);
        assertNull(xmlSignatureOutput.getBytes());
    }

    public static class MockTransformC14N extends TransformC14N {

        static {
            org.apache.xml.security.Init.init();
        }

        @Override
        public XMLSignatureInput enginePerformTransform(XMLSignatureInput input, OutputStream os,
                                                        Element transformElement, String baseURI,
                                                        boolean secureValidation) throws CanonicalizationException {
            return super.enginePerformTransform(input, os, transformElement, baseURI, secureValidation);
        }

    }
}