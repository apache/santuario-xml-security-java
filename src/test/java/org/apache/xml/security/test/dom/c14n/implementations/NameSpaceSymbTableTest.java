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


import java.util.ArrayList;
import java.util.List;

import org.apache.xml.security.c14n.implementations.NameSpaceSymbTable;
import org.apache.xml.security.test.dom.TestUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;


class NameSpaceSymbTableTest {
    private static final Attr node1, node2;
    static {
        try {
            Document doc = TestUtils.newDocument();
            node1 = doc.createAttributeNS("a","b");
            node2 = doc.createAttributeNS("b","c");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void testNullFirstXmlns() {
        NameSpaceSymbTable ns = new NameSpaceSymbTable();
        assertNull(ns.getMapping("xmlns"));
    }

    @Test
    void testXmlnsPut() {
        NameSpaceSymbTable ns = new NameSpaceSymbTable();
        ns.push();
        ns.addMapping("xmlns", "http://a", node1);
        assertEquals(node1, ns.getMapping("xmlns"));
    }

    @Test
    void testXmlnsMap() {
        NameSpaceSymbTable ns = new NameSpaceSymbTable();
        ns.push();
        ns.addMapping("xmlns", "http://a", node1);
        assertEquals(node1, ns.getMapping("xmlns"));
        ns.pop();
        assertEquals(null, ns.getMapping("xmlns"));
    }

    @Test
    void testXmlnsMap2() {
        NameSpaceSymbTable ns = new NameSpaceSymbTable();
        ns.push();
        ns.push();
        ns.addMapping("xmlns", "http://a", node1);
        ns.pop();
        ns.pop();
        assertEquals(null, ns.getMapping("xmlns"));
    }

    @Test
    void testXmlnsPrefix() {
        NameSpaceSymbTable ns = new NameSpaceSymbTable();
        ns.push();
        ns.addMapping("xmlns", "http://a", node1);
        assertEquals(node1, ns.getMapping("xmlns"));
        ns.push();
        ns.addMapping("xmlns", "http://a", node1);
        assertEquals(null, ns.getMapping("xmlns"));
        ns.push();
        ns.addMapping("xmlns", "http://b", node1);
        assertEquals(node1, ns.getMapping("xmlns"));
    }

    @Test
    void testXmlnsRemovePrefix() {
        NameSpaceSymbTable ns = new NameSpaceSymbTable();
        ns.push();
        ns.push();
        ns.addMapping("xmlns", "http://a", node1);
        assertEquals(node1, ns.getMapping("xmlns"));
        ns.pop();
        assertNull(ns.getMapping("xmlns"));
    }

    @Test
    void testPrefix() {
        NameSpaceSymbTable ns = new NameSpaceSymbTable();
        ns.push();
        ns.addMapping("a", "http://a", node1);
        assertEquals(node1, ns.getMapping("a"));
        ns.push();
        assertNull(ns.getMapping("a"));
        ns.push();
        ns.addMapping("a", "http://c",node1);
        assertEquals(node1, ns.getMapping("a"));
        ns.pop();
        ns.push();
        assertNull(ns.getMapping("a"));
        ns.addMapping("a", "http://c",node1);
        assertEquals(node1, ns.getMapping("a"));
    }

    @Test
    void testSeveralPrefixes() {
        NameSpaceSymbTable ns = new NameSpaceSymbTable();
        ns.push();
        ns.addMapping("a", "http://a",node1);
        ns.addMapping("b", "http://b",node2);
        assertEquals(node1, ns.getMapping("a"));
        assertEquals(node2, ns.getMapping("b"));
        ns.push();
        assertNull(ns.getMapping("a"));
    }

    @Test
    void testSeveralPrefixes2() {
        NameSpaceSymbTable ns = new NameSpaceSymbTable();
        ns.push();
        ns.addMapping("a", "http://a",node1);
        ns.push();
        assertEquals(node1, ns.getMapping("a"));
        ns.pop();
        assertEquals(node1, ns.getMapping("a"));
    }

    @Test
    void testGetUnrenderedNodes() {
        NameSpaceSymbTable ns = new NameSpaceSymbTable();
        ns.push();
        List<Attr> l = new ArrayList<>();
        ns.addMapping("xmlns", "http://a", node1);
        ns.push();
        ns.getUnrenderedNodes(l);
        assertTrue(l.contains(node1));
        Attr n = (Attr)ns.addMappingAndRender("xmlns", "", node2);
        assertNotNull(n, "xmlns=\"\" not rendered");
        assertEquals(n, node2);
    }

    @Test
    void testUnrederedNodes() {
        NameSpaceSymbTable ns = new NameSpaceSymbTable();
        ns.push();
        List<Attr> l = new ArrayList<>();
        ns.getUnrenderedNodes(l);
        assertTrue(l.isEmpty());
        l.clear();
        ns.push();
        ns.addMapping("xmlns","http://a", node1);
        ns.addMapping("a", "http://a", node2);

        ns.push();

        ns.getUnrenderedNodes(l);
        assertTrue(l.contains(node1));
        assertTrue(l.contains(node2));
        ns.push();
        l.clear();
        ns.getUnrenderedNodes(l);
        assertFalse(l.contains(node1));
        assertFalse(l.contains(node2));
        ns.pop();
        ns.pop();
        l.clear();
        ns.getUnrenderedNodes(l);
        assertTrue(l.contains(node1));
        assertTrue(l.contains(node2));
    }

    @Test
    void testBug38655() {
        NameSpaceSymbTable ns = new NameSpaceSymbTable();
        ns.push();

        ns.addMappingAndRender("generated-command", "http://foo.com/command",node1);
        ns.addMappingAndRender("generated-event", "http://foo.com/event",node1);
        ns.addMappingAndRender("command", "http://foo.com/command",node1);
        ns.addMappingAndRender("ui", "http://foo.com/ui", node1);
        ns.addMappingAndRender("event", "http://foo.com/event", node1);
        ns.addMappingAndRender("instruction", "http://foo/instruction", node1);
        ns.addMappingAndRender("directory", "http://foo.com/io/directory", node1);
        ns.addMappingAndRender("function", "http://foo.com/function", node1);
        ns.addMappingAndRender("xmlns", "http://www.w3.org/1999/xhtml", node1);
        ns.addMappingAndRender("ctrl", "http://foo.com/controls", node1);
        ns.addMappingAndRender("wiki", "http://foo.com/samples/wiki", node1);
    }
}