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


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.apache.xml.security.c14n.implementations.Canonicalizer11_OmitComments;
import org.apache.xml.security.utils.XMLUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * This is a test for Santuario-191:
 *
 * https://issues.apache.org/jira/browse/SANTUARIO-191
 *
 * An xml:Id attribute is appearing in a child element, contrary to the C14n11 spec.
 */
public class Santuario191Test {

    private static final String INPUT_DATA =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      + "<test xml:id=\"testid1\">"
      + "<data>"
      + "    <user1>Alice</user1>"
      + "    <user2>Bob</user2>"
      + "</data>"
      + "</test>";
    private static final String EXPECTED_RESULT =
        "<data>"
      + "    <user1>Alice</user1>"
      + "    <user2>Bob</user2>"
      + "</data>";

    static {
        org.apache.xml.security.Init.init();
    }

    @org.junit.jupiter.api.Test
    public void testSantuario191() throws Exception {
        //
        // Parse the Data
        //
        Document doc = null;
        try (InputStream is = new ByteArrayInputStream(INPUT_DATA.getBytes(StandardCharsets.UTF_8))) {
            doc = XMLUtils.read(is, false);
        }

        //
        // Canonicalize the data
        //
        NodeList dataNodes = doc.getElementsByTagName("data");
        Canonicalizer11_OmitComments c14ner = new Canonicalizer11_OmitComments();
        byte[] result = c14ner.engineCanonicalizeSubTree(dataNodes.item(0));

        //
        // Test against expected result
        //
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(result);
        assertEquals(EXPECTED_RESULT, out.toString(StandardCharsets.UTF_8.name()));
    }

}