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


import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.apache.xml.security.test.XmlSecTestEnvironment.resolvePath;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit test for
 * {@link org.apache.xml.security.c14n.implementations.Canonicalizer11}
 */
public class Canonicalizer11Test {

    static org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(Canonicalizer11Test.class);

    static {
        org.apache.xml.security.Init.init();
    }

    /** Field prefix */
    private final Path prefix;

    public Canonicalizer11Test() {
        prefix = resolvePath("src", "test", "resources", "org", "apache", "xml", "security", "c14n");
    }

    /**
     * 3.1 PIs, Comments, and Outside of Document Element
     */
    @Test
    public void test31withCommentsSubtree() throws Exception {
        String descri =
            "3.1: PIs, Comments, and Outside of Document Element. (commented)";

        String fileIn = resolvePath(prefix, "in", "31_input.xml").toString();
        Path fileRef = resolvePath(prefix, "in", "31_c14n-comments.xml");
        File fileOut = resolveFile(prefix, "out", "xpath_31_output-comments.xml");
        String c14nURI = Canonicalizer.ALGO_ID_C14N11_WITH_COMMENTS;
        String xpath = null;

        assertTrue(c14nAndCompare(fileIn, fileRef, fileOut, c14nURI, xpath), descri);
    }

    /**
     * 3.2 Whitespace in Document Content

     * @see <A HREF="http://www.w3.org/TR/2001/PR-xml-c14n-20010119#Example-WhitespaceInContent">the example from the spec</A>
     */
    @Test
    public void test32subtree() throws Exception {
        String descri = "3.2 Whitespace in Document Content. (uncommented)";
        String fileIn = resolvePath(prefix, "in", "32_input.xml").toString();
        Path fileRef = resolvePath(prefix, "in", "32_c14n.xml");
        File fileOut = resolveFile(prefix, "out", "xpath_32_output.xml");
        String c14nURI = Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS;
        String xpath = null;

        assertTrue(c14nAndCompare(fileIn, fileRef, fileOut, c14nURI, xpath), descri);
    }

    /**
     * 3.3 Start and End Tags
     *
     * @see <A HREF="http://www.w3.org/TR/2001/PR-xml-c14n-20010119#Example-SETags">the example from the spec</A>
     */
    @Test
    public void test33subtree() throws Exception  {
        String descri = "3.3 Start and End Tags. (uncommented)";
        String fileIn = resolvePath(prefix, "in", "33_input.xml").toString();
        Path fileRef = resolvePath(prefix, "in", "33_c14n.xml");
        File fileOut = resolveFile(prefix, "out", "xpath_33_output.xml");
        String c14nURI = Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS;
        String xpath = null;    // Canonicalizer.XPATH_C14N_OMIT_COMMENTS_SINGLE_NODE;

        assertTrue(c14nAndCompare(fileIn, fileRef, fileOut, c14nURI, xpath), descri);
    }

    /**
     * 3.4 Character Modifications and Character References
     *
     * @see #test34validatingParser
     * @see <A HREF="http://www.w3.org/TR/2001/PR-xml-c14n-20010119#Example-Chars">the example from the spec</A>
     */
    @Test
    public void test34() throws Exception {
        String descri =
            "3.4 Character Modifications and Character References. (uncommented)";
        String fileIn = resolvePath(prefix, "in", "34_input.xml").toString();
        Path fileRef = resolvePath(prefix, "in", "34_c14n.xml");
        File fileOut = resolveFile(prefix, "out", "xpath_34_output.xml");
        String c14nURI = Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS;
        String xpath = null;

        assertTrue(c14nAndCompare(fileIn, fileRef, fileOut, c14nURI, xpath), descri);
    }

    /**
     * 3.5 Entity References
     *
     * @see <A HREF="http://www.w3.org/TR/2001/PR-xml-c14n-20010119#Example-Entities">the example from the spec</A>
     */
    @Test
    public void test35subtree() throws Exception {
        String descri = "3.5 Entity References. (uncommented)";
        String fileIn = resolvePath(prefix, "in", "35_input.xml").toString();
        Path fileRef = resolvePath(prefix, "in", "35_c14n.xml");
        File fileOut = resolveFile(prefix, "out", "xpath_35_output.xml");
        String c14nURI = Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS;
        String xpath = null;

        assertTrue(c14nAndCompare(fileIn, fileRef, fileOut, c14nURI, xpath), descri);
    }

    /**
     * 3.6 UTF-8 Encoding
     *
     * @see <A HREF="http://www.w3.org/TR/2001/PR-xml-c14n-20010119#Example-UTF8">the example from the spec</A>
     */
    @Test
    public void test36subtree() throws Exception {
        String descri = "3.6 UTF-8 Encoding. (uncommented)";
        String fileIn = resolvePath(prefix, "in", "36_input.xml").toString();
        Path fileRef = resolvePath(prefix, "in", "36_c14n.xml");
        File fileOut = resolveFile(prefix, "out", "xpath_36_output.xml");
        String c14nURI = Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS;
        String xpath = null;

        assertTrue(c14nAndCompare(fileIn, fileRef, fileOut, c14nURI, xpath), descri);
    }

    /**
     * 3.7 Document Subsets
     *
     * @see <A HREF="http://www.w3.org/TR/2001/PR-xml-c14n-20010119#Example-DocSubsets">the example from the spec</A>
     */
    @Test
    public void test37() throws Exception {
        String descri = "3.7 Document Subsets. (uncommented)";
        String fileIn = resolvePath(prefix, "in", "37_input.xml").toString();
        Path fileRef = resolvePath(prefix, "in", "37_c14n.xml");
        File fileOut = resolveFile(prefix, "out", "xpath_37_output.xml");
        String c14nURI = Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS;

        Map<String, String> namespace = new HashMap<>();
        namespace.put("ietf", "http://www.ietf.org");
        String xpath =
            "(//. | //@* | //namespace::*)"
            + "[ "
            + "self::ietf:e1 or "
            + "(parent::ietf:e1 and not(self::text() or self::e2)) or "
            + "count(id(\"E3\")|ancestor-or-self::node()) = count(ancestor-or-self::node()) "
            + "]";

        assertTrue(c14nAndCompare(fileIn, fileRef, fileOut, c14nURI, xpath, namespace), descri);
    }

    /**
     * 3.8 Document Subsets and XML Attributes
     */
    @Test
    public void test38() throws Exception {
        String descri = "3.8 Document Subsets and XML Attributes (uncommented)";
        String fileIn = resolvePath(prefix, "in", "38_input.xml").toString();
        Path fileRef = resolvePath(prefix, "in", "38_c14n.xml");
        File fileOut = resolveFile(prefix, "out", "xpath_38_output.xml");
        String c14nURI = Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS;

        Map<String, String> namespace = new HashMap<>();
        namespace.put("ietf", "http://www.ietf.org");
        String xpath =
            "(//. | //@* | //namespace::*)"
            + "[ "
            + "self::ietf:e1 or "
            + "(parent::ietf:e1 and not(self::text() or self::e2)) or "
            + "count(id(\"E3\")|ancestor-or-self::node()) = count(ancestor-or-self::node()) "
            + "]";

        assertTrue(c14nAndCompare(fileIn, fileRef, fileOut, c14nURI, xpath, namespace), descri);
    }

    private boolean c14nAndCompare(
                                   String fileIn,
                                   Path fileRef,
                                   File fileOut,
                                   String c14nURI,
                                   String xpath
                               ) throws Exception {
        Map<String, String> namespace = new HashMap<>();
        return c14nAndCompare(fileIn, fileRef, fileOut,
            c14nURI, xpath, namespace);
    }

    private boolean c14nAndCompare(
        String fileIn,
        Path fileRef,
        File fileOut,
        String c14nURI,
        String xpath,
        Map<String, String> namespaces
    ) throws Exception {

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setNamespaceAware(true);

        Document doc = dbf.newDocumentBuilder().parse(fileIn);

        Canonicalizer c14n = Canonicalizer.getInstance(c14nURI);
        byte[] c14nBytes = null;

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            if (xpath == null) {
                c14n.canonicalizeSubtree(doc, baos);
                c14nBytes = baos.toByteArray();
            } else {
                XPathFactory xpf = XPathFactory.newInstance();
                XPath xPath = xpf.newXPath();
                DSNamespaceContext namespaceContext =
                    new DSNamespaceContext(namespaces);
                xPath.setNamespaceContext(namespaceContext);

                NodeList nl = (NodeList)xPath.evaluate(xpath, doc, XPathConstants.NODESET);

                c14n.canonicalizeXPathNodeSet(XMLUtils.convertNodelistToSet(nl), baos);
                c14nBytes = baos.toByteArray();
            }
        }

        // org.xml.sax.InputSource refIs = resolver.resolveEntity(null, fileRef);
        // byte[] refBytes = JavaUtils.getBytesFromStream(refIs.getByteStream());
        byte[] refBytes = Files.readAllBytes(fileRef);

        // if everything is OK, result is true; we do a binary compare, byte by byte
        boolean result = java.security.MessageDigest.isEqual(refBytes, c14nBytes);

        if (!result) {
            if (!fileOut.exists()) {
                File parent = new File(fileOut.getParent());
                parent.mkdirs();
                fileOut.createNewFile();
            }
            try (FileOutputStream fos = new FileOutputStream(fileOut)) {
                fos.write(c14nBytes);
                LOG.debug("Wrote erroneous result to file " + fileOut.toURI().toURL().toString());
                assertEquals(new String(refBytes), new String(c14nBytes));
            }
        }

        return result;
    }

}