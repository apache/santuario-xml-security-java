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
package org.apache.xml.security.test.stax.c14n;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;

import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.transformer.canonicalizer.Canonicalizer11_OmitCommentsTransformer;
import org.apache.xml.security.test.stax.utils.XMLSecEventAllocator;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Canonical XML 1.1 of a subtree must output the apex element's own xml:id, must not inherit
 * xml:id, and must output xml:base resolved against the ancestors' xml:base ("xml:base fixup"),
 * exactly as the DOM implementation does.
 */
class Canonicalizer11ApexTest {

    static {
        org.apache.xml.security.Init.init();
    }

    @ParameterizedTest
    @ValueSource(strings = {
        // own xml:id and absolute xml:base, ancestor xml:base
        "<root xml:base=\"http://parent/\"><e xml:id=\"a\" xml:base=\"http://x/\" attr=\"1\"><c/></e></root>",
        // own relative xml:base resolved against an ancestor's xml:base
        "<r xml:base=\"http://host/a/\"><e xml:base=\"b/c\"><c/></e></r>",
        // no own xml:base: the ancestor's value is output
        "<r xml:base=\"http://host/a/\"><m><e attr=\"1\"/></m></r>",
        // xml:id is not inherited, xml:lang and xml:space are
        "<r xml:id=\"r1\" xml:lang=\"en\" xml:space=\"preserve\"><e xml:id=\"e1\"><c xml:id=\"c1\"/></e></r>",
        // descendants keep their own xml:base unchanged
        "<r xml:base=\"http://host/\"><e><c xml:base=\"sub/\"/></e></r>",
        // no xml:* attributes at all
        "<r a=\"1\"><e b=\"2\"><c/></e></r>"
    })
    void testApexMatchesDOM(String xml) throws Exception {
        assertEquals(canonicalizeWithDOM(xml), canonicalizeWithStAX(xml));
    }

    /**
     * With several ancestors carrying xml:base, the apex's xml:base is resolved against them
     * nearest first (RFC 3986). (The DOM implementation currently resolves them in the opposite
     * order, so it is not used as the reference here.)
     */
    @Test
    void testXmlBaseResolvedAgainstAncestorChain() throws Exception {
        assertEquals("<e xml:base=\"http://host/a/b/c/f/g\"><c></c></e>", canonicalizeWithStAX(
            "<r xml:base=\"http://host/a/b/\"><m xml:base=\"c/d/\"><e xml:base=\"../f/g\"><c/></e></m></r>"));
        assertEquals("<e attr=\"1\" xml:base=\"http://host/a/b/\"></e>", canonicalizeWithStAX(
            "<r xml:base=\"http://host/a/\"><m xml:base=\"b/\"><e attr=\"1\"/></m></r>"));
    }

    private static String canonicalizeWithDOM(String xml) throws Exception {
        Document doc = XMLUtils.read(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)), false);
        Node e = doc.getElementsByTagName("e").item(0);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS).canonicalizeSubtree(e, baos);
        return baos.toString(StandardCharsets.UTF_8);
    }

    private static String canonicalizeWithStAX(String xml) throws Exception {
        XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
        xmlInputFactory.setEventAllocator(new XMLSecEventAllocator());
        XMLEventReader reader = xmlInputFactory.createXMLEventReader(
            new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        Canonicalizer11_OmitCommentsTransformer c14n = new Canonicalizer11_OmitCommentsTransformer();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        c14n.setOutputStream(baos);
        int depth = 0;
        while (reader.hasNext()) {
            XMLSecEvent event = (XMLSecEvent) reader.nextEvent();
            if (depth == 0 && !(event.isStartElement() && "e".equals(event.asStartElement().getName().getLocalPart()))) {
                continue;
            }
            c14n.transform(event);
            if (event.isStartElement()) {
                depth++;
            } else if (event.isEndElement() && --depth == 0) {
                break;
            }
        }
        c14n.doFinal();
        return baos.toString(StandardCharsets.UTF_8);
    }
}
