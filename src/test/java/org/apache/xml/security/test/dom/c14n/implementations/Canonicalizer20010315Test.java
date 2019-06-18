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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.utils.JavaUtils;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * Unit test for
 * {@link org.apache.xml.security.c14n.implementations.Canonicalizer20010315WithXPath}
 *
 */
public class Canonicalizer20010315Test {

    static org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(Canonicalizer20010315Test.class);

    static {
        org.apache.xml.security.Init.init();
    }

    /** Field prefix */
    private String prefix;

    public Canonicalizer20010315Test() {
        prefix = "src/test/resources/org/apache/xml/security/c14n/";
        String basedir = System.getProperty("basedir");
        if (basedir != null && !"".equals(basedir)) {
            prefix = basedir + "/" + prefix;
        }
    }

    /**
     * 3.1 PIs, Comments, and Outside of Document Element
     */
    @org.junit.jupiter.api.Test
    public void test31withCommentsSubtree() throws Exception {
        String descri =
            "3.1: PIs, Comments, and Outside of Document Element. (commented)";

        String fileIn = prefix + "in/31_input.xml";
        String fileRef = prefix + "in/31_c14n-comments.xml";
        String fileOut = prefix + "out/xpath_31_output-comments.xml";
        String c14nURI = Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS;
        String xpath = null;

        assertTrue(c14nAndCompare(fileIn, fileRef, fileOut, c14nURI, xpath), descri);
    }

    /**
     * 3.1 PIs, Comments, and Outside of Document Element
     */
    @org.junit.jupiter.api.Test
    public void test31withCommentsSubset() throws Exception {
        String descri =
            "3.1: PIs, Comments, and Outside of Document Element. (commented)";

        String fileIn = prefix + "in/31_input.xml";
        String fileRef = prefix + "in/31_c14n-comments.xml";
        String fileOut = prefix + "out/xpath_31_output-comments.xml";
        String c14nURI = Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS;
        String xpath = Canonicalizer.XPATH_C14N_WITH_COMMENTS_SINGLE_NODE;

        assertTrue(c14nAndCompare(fileIn, fileRef, fileOut, c14nURI, xpath), descri);
    }

    /**
     * 3.1 PIs, Comments, and Outside of Document Element

     * @see <A HREF="http://www.w3.org/TR/2001/PR-xml-c14n-20010119#Example-OutsideDoc">the example from the spec</A>
     */
    @org.junit.jupiter.api.Test
    public void test31subtree() throws Exception {
        String descri =
            "3.1: PIs, Comments, and Outside of Document Element. (uncommented)";
        String fileIn = prefix + "in/31_input.xml";
        String fileRef = prefix + "in/31_c14n.xml";
        String fileOut = prefix + "out/xpath_31_output.xml";
        String c14nURI = Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS;
        String xpath = null;

        assertTrue(c14nAndCompare(fileIn, fileRef, fileOut, c14nURI, xpath), descri);
    }

    /**
     * 3.1 PIs, Comments, and Outside of Document Element
     *
     * @see <A HREF="http://www.w3.org/TR/2001/PR-xml-c14n-20010119#Example-OutsideDoc">the example from the spec</A>
     */
    @org.junit.jupiter.api.Test
    public void test31subset() throws Exception {

        String descri =
            "3.1: PIs, Comments, and Outside of Document Element. (uncommented)";
        String fileIn = prefix + "in/31_input.xml";
        String fileRef = prefix + "in/31_c14n.xml";
        String fileOut = prefix + "out/xpath_31_output.xml";
        String c14nURI = Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS;
        String xpath = Canonicalizer.XPATH_C14N_WITH_COMMENTS_SINGLE_NODE;

        assertTrue(c14nAndCompare(fileIn, fileRef, fileOut, c14nURI, xpath), descri);
    }

    /**
     * 3.2 Whitespace in Document Content
     *
     * @see <A HREF="http://www.w3.org/TR/2001/PR-xml-c14n-20010119#Example-WhitespaceInContent">the example from the spec</A>
     */
    @org.junit.jupiter.api.Test
    public void test32subtree() throws Exception {
        String descri = "3.2 Whitespace in Document Content. (uncommented)";
        String fileIn = prefix + "in/32_input.xml";
        String fileRef = prefix + "in/32_c14n.xml";
        String fileOut = prefix + "out/xpath_32_output.xml";
        String c14nURI = Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS;
        String xpath = null;

        assertTrue(c14nAndCompare(fileIn, fileRef, fileOut, c14nURI, xpath), descri);
    }

    /**
     * 3.2 Whitespace in Document Content
     *
     * @see <A HREF="http://www.w3.org/TR/2001/PR-xml-c14n-20010119#Example-WhitespaceInContent">the example from the spec</A>
     */
    @org.junit.jupiter.api.Test
    public void test32subset() throws Exception {
        String descri = "3.2 Whitespace in Document Content. (uncommented)";
        String fileIn = prefix + "in/32_input.xml";
        String fileRef = prefix + "in/32_c14n.xml";
        String fileOut = prefix + "out/xpath_32_output.xml";
        String c14nURI = Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS;
        String xpath = Canonicalizer.XPATH_C14N_WITH_COMMENTS_SINGLE_NODE;

        assertTrue(c14nAndCompare(fileIn, fileRef, fileOut, c14nURI, xpath), descri);
    }

    /**
     * 3.3 Start and End Tags
     *
     * @see <A HREF="http://www.w3.org/TR/2001/PR-xml-c14n-20010119#Example-SETags">the example from the spec</A>
     */
    @org.junit.jupiter.api.Test
    public void test33subtree() throws Exception {
        String descri = "3.3 Start and End Tags. (uncommented)";
        String fileIn = prefix + "in/33_input.xml";
        String fileRef = prefix + "in/33_c14n.xml";
        String fileOut = prefix + "out/xpath_33_output.xml";
        String c14nURI = Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS;
        String xpath = null;    // Canonicalizer.XPATH_C14N_OMIT_COMMENTS_SINGLE_NODE;

        assertTrue(c14nAndCompare(fileIn, fileRef, fileOut, c14nURI, xpath), descri);
    }

    @org.junit.jupiter.api.Test
    public void test33subset() throws Exception {
        String descri = "3.3 Start and End Tags. (uncommented)";
        String fileIn = prefix + "in/33_input.xml";
        String fileRef = prefix + "in/33_c14n.xml";
        String fileOut = prefix + "out/xpath_33_output.xml";
        String c14nURI = Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS;
        String xpath = Canonicalizer.XPATH_C14N_WITH_COMMENTS_SINGLE_NODE;

        assertTrue(c14nAndCompare(fileIn, fileRef, fileOut, c14nURI, xpath), descri);
    }

    /**
     * 3.4 Character Modifications and Character References
     *
     * @see #test34validatingParser
     * @see <A HREF="http://www.w3.org/TR/2001/PR-xml-c14n-20010119#Example-Chars">the example from the spec</A>
     */
    @org.junit.jupiter.api.Test
    public void test34() throws Exception {
        String descri =
            "3.4 Character Modifications and Character References. (uncommented)";
        String fileIn = prefix + "in/34_input.xml";
        String fileRef = prefix + "in/34_c14n.xml";
        String fileOut = prefix + "out/xpath_34_output.xml";
        String c14nURI = Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS;
        String xpath = null;

        assertTrue(c14nAndCompare(fileIn, fileRef, fileOut, c14nURI, xpath), descri);
    }

    /**
     * 3.4 Character Modifications and Character References (patched to run on validating Parsers)
     * <P>
     * <A HREF="http://www.w3.org/TR/2001/PR-xml-c14n-20010119"> The spec</A> states that:
     * <P>
     * Note: The last element, normId, is well-formed but violates a validity
     * constraint for attributes of type ID. For testing canonical XML
     * implementations based on validating processors, remove the line
     * containing this element from the input and canonical form. In general,
     * XML consumers should be discouraged from using this feature of XML.
     *
     * @see <A HREF="http://www.w3.org/TR/2001/PR-xml-c14n-20010119#Example-Chars">the example from the spec</A>
     */
    @org.junit.jupiter.api.Test
    public void test34subtree() throws Exception {
        String descri =
            "3.4 Character Modifications and Character References. (uncommented, patched to run on validating Parsers)";
        String fileIn = prefix + "in/34_input_validatingParser.xml";
        String fileRef = prefix + "in/34_c14n_validatingParser.xml";
        String fileOut = prefix + "out/xpath_34_output_validatingParser.xml";
        String c14nURI = Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS;
        String xpath = null;

        assertTrue(c14nAndCompare(fileIn, fileRef, fileOut, c14nURI, xpath), descri);
    }

    /**
     * 3.4 Character Modifications and Character References (patched to run on validating Parsers)
     * <P>
     * <A HREF="http://www.w3.org/TR/2001/PR-xml-c14n-20010119"> The spec</A> states that:
     * <P>
     * Note: The last element, normId, is well-formed but violates a validity
     * constraint for attributes of type ID. For testing canonical XML
     * implementations based on validating processors, remove the line
     * containing this element from the input and canonical form. In general,
     * XML consumers should be discouraged from using this feature of XML.
     *
     * @see <A HREF="http://www.w3.org/TR/2001/PR-xml-c14n-20010119#Example-Chars">the example from the spec</A>
     */
    @org.junit.jupiter.api.Test
    public void test34subset() throws Exception {

        String descri =
            "3.4 Character Modifications and Character References. (uncommented, patched to run on validating Parsers)";
        String fileIn = prefix + "in/34_input_validatingParser.xml";
        String fileRef = prefix + "in/34_c14n_validatingParser.xml";
        String fileOut = prefix + "out/xpath_34_output_validatingParser.xml";
        String c14nURI = Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS;
        String xpath = Canonicalizer.XPATH_C14N_WITH_COMMENTS_SINGLE_NODE;

        assertTrue(c14nAndCompare(fileIn, fileRef, fileOut, c14nURI, xpath), descri);
    }

    /**
     * 3.5 Entity References
     *
     * @see <A HREF="http://www.w3.org/TR/2001/PR-xml-c14n-20010119#Example-Entities">the example from the spec</A>
     */
    @org.junit.jupiter.api.Test
    public void test35subtree() throws Exception{
        String descri = "3.5 Entity References. (uncommented)";
        String fileIn = prefix + "in/35_input.xml";
        String fileRef = prefix + "in/35_c14n.xml";
        String fileOut = prefix + "out/xpath_35_output.xml";
        String c14nURI = Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS;
        String xpath = null;

        assertTrue(c14nAndCompare(fileIn, fileRef, fileOut, c14nURI, xpath), descri);
    }

    /**
     * 3.5 Entity References
     *
     * @see <A HREF="http://www.w3.org/TR/2001/PR-xml-c14n-20010119#Example-Entities">the example from the spec</A>
     */
    @org.junit.jupiter.api.Test
    public void test35subset() throws Exception {
        String descri = "3.5 Entity References. (uncommented)";
        String fileIn = prefix + "in/35_input.xml";
        String fileRef = prefix + "in/35_c14n.xml";
        String fileOut = prefix + "out/xpath_35_output.xml";
        String c14nURI = Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS;
        String xpath = Canonicalizer.XPATH_C14N_WITH_COMMENTS_SINGLE_NODE;

        assertTrue(c14nAndCompare(fileIn, fileRef, fileOut, c14nURI, xpath), descri);
    }

    /**
     * 3.6 UTF-8 Encoding
     *
     * @see <A HREF="http://www.w3.org/TR/2001/PR-xml-c14n-20010119#Example-UTF8">the example from the spec</A>
     */
    @org.junit.jupiter.api.Test
    public void test36subtree() throws Exception {
        String descri = "3.6 UTF-8 Encoding. (uncommented)";
        String fileIn = prefix + "in/36_input.xml";
        String fileRef = prefix + "in/36_c14n.xml";
        String fileOut = prefix + "out/xpath_36_output.xml";
        String c14nURI = Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS;
        String xpath = null;

        assertTrue(c14nAndCompare(fileIn, fileRef, fileOut, c14nURI, xpath), descri);
    }

    /**
     * 3.6 UTF-8 Encoding
     *
     * @see <A HREF="http://www.w3.org/TR/2001/PR-xml-c14n-20010119#Example-UTF8">the example from the spec</A>
     */
    @org.junit.jupiter.api.Test
    public void test36subset() throws Exception {
        String descri = "3.6 UTF-8 Encoding. (uncommented)";
        String fileIn = prefix + "in/36_input.xml";
        String fileRef = prefix + "in/36_c14n.xml";
        String fileOut = prefix + "out/xpath_36_output.xml";
        String c14nURI = Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS;
        String xpath = Canonicalizer.XPATH_C14N_WITH_COMMENTS_SINGLE_NODE;

        assertTrue(c14nAndCompare(fileIn, fileRef, fileOut, c14nURI, xpath), descri);
    }

    /**
     * 3.7 Document Subsets
     *
     * @see <A HREF="http://www.w3.org/TR/2001/PR-xml-c14n-20010119#Example-DocSubsets">the example from the spec</A>
     */
    @org.junit.jupiter.api.Test
    public void test37() throws Exception {
        String descri = "3.7 Document Subsets. (uncommented)";
        String fileIn = prefix + "in/37_input.xml";
        String fileRef = prefix + "in/37_c14n.xml";
        String fileOut = prefix + "out/xpath_37_output.xml";
        String c14nURI = Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS;

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
     * 3.7 Document Subsets
     *
     * @see <A HREF="http://www.w3.org/TR/2001/PR-xml-c14n-20010119#Example-DocSubsets">the example from the spec</A>
     */
    @org.junit.jupiter.api.Test
    public void test37byNodeList() throws Exception {

        //String descri = "3.7 Document Subsets. (uncommented), c14n by NodeList";
        String fileIn = prefix + "in/37_input.xml";
        String fileRef = prefix + "in/37_c14n.xml";
        //String c14nURI = Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS;

        Document doc = XMLUtils.read(new FileInputStream(fileIn), false);

        String xpath = "(//. | //@* | //namespace::*)"
            + "[ "
            + "self::ietf:e1 or "
            + "(parent::ietf:e1 and not(self::text() or self::e2)) or "
            + "count(id(\"E3\")|ancestor-or-self::node()) = count(ancestor-or-self::node()) "
            + "]";

        Map<String, String> namespace = new HashMap<>();
        namespace.put("ietf", "http://www.ietf.org");

        XPathFactory xpf = XPathFactory.newInstance();
        XPath xPath = xpf.newXPath();
        DSNamespaceContext namespaceContext =
            new DSNamespaceContext(namespace);
        xPath.setNamespaceContext(namespaceContext);

        NodeList nodes = (NodeList)xPath.evaluate(xpath, doc, XPathConstants.NODESET);
        Canonicalizer c14n =
            Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
        byte[] c14nBytes = c14n.canonicalizeXPathNodeSet(nodes);
        InputStream refStream = new FileInputStream(fileRef);
        byte[] refBytes = JavaUtils.getBytesFromStream(refStream);
        assertEquals(new String(refBytes),new String(c14nBytes));
    }

    /**
     * Note: This specification supports the recent XML plenary decision to
     * deprecate relative namespace URIs as follows: implementations of XML
     * canonicalization MUST report an operation failure on documents containing
     * relative namespace URIs. XML canonicalization MUST NOT be implemented
     * with an XML parser that converts relative URIs to absolute URIs.
     *
     * Implementations MUST report an operation failure on documents containing
     * relative namespace URIs.
     */
    @org.junit.jupiter.api.Test
    public void testRelativeNSbehaviour() throws Exception {

        //J-
        String inputStr = ""
            + "<absolute:correct xmlns:absolute='http://www.absolute.org/#likeVodka'>"
            + "<relative:incorrect xmlns:relative='../cheating#away'>"
            + "</relative:incorrect>"
            + "</absolute:correct>"
            + "\n"
            + "";
        //J+

        Document doc = null;
        try (InputStream is = new ByteArrayInputStream(inputStr.getBytes())) {
            doc = XMLUtils.read(is, false);
        }
        boolean weCatchedTheRelativeNS = false;

        try {
            Canonicalizer c14n =
                Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
            c14n.canonicalizeSubtree(doc);

        } catch (CanonicalizationException cex) {
            // if we reach this point - good.
            LOG.debug("We catched the C14nEx, that's good: " + cex.getMessage());
            weCatchedTheRelativeNS = true;
        }

        assertTrue(weCatchedTheRelativeNS, "We did not catch the relative namespace");
    }

    /**
     * The XPath data model represents data using UCS characters.
     * Implementations MUST use XML processors that support UTF-8 and UTF-16
     * and translate to the UCS character domain. For UTF-16, the leading byte
     * order mark is treated as an artifact of encoding and stripped from the
     * UCS character data (subsequent zero width non-breaking spaces appearing
     * within the UTF-16 data are not removed) [UTF-16, Section 3.2]. Support
     * for ISO-8859-1 encoding is RECOMMENDED, and all other character encodings
     * are OPTIONAL.
     */
    @org.junit.jupiter.api.Test
    public void testTranslationFromUTF16toUTF8() throws Exception {
        String val =
            "<UTF16>The german &amp;auml (which is Unicode &amp;#xE4;):  &quot;&#xE4;&quot;</UTF16>";
        byte[] utf16 = convertToUTF16(val.getBytes());
        Canonicalizer c14n =
            Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
        byte[] c14nBytes = c14n.canonicalize(utf16);
        InputStream refStream = new FileInputStream(prefix + "/in/testTranslationFromUTF16toUTF8.xml");
        byte[] refBytes = JavaUtils.getBytesFromStream(refStream);
        boolean equal = java.security.MessageDigest.isEqual(refBytes, c14nBytes);

        assertTrue(equal, "Parser does not translate to UCS character domain");
    }

    /**
     * Method testXMLAttributes1
     */
    @org.junit.jupiter.api.Test
    public void testXMLAttributes1() throws Exception {
        //J-
        String input = ""
            + "<included xml:lang='de'>"
            + "<notIncluded xml:lang='de'>"
            + "<notIncluded xml:lang='uk'>"
            + "<included                 >"
            + "</included>"
            + "</notIncluded>"
            + "</notIncluded>"
            + "</included>";

        String definedOutput = ""
            + "<included xml:lang=\"de\">"
            + "<included xml:lang=\"uk\">"
            + "</included>"
            + "</included>";
        //J+
        assertTrue(doTestXMLAttributes(input, definedOutput));
    }

    /**
     * Method testXMLAttributes2
     */
    @org.junit.jupiter.api.Test
    public void testXMLAttributes2() throws Exception {
        //J-
        String input = ""
            + "<included xml:lang='uk'>"
            + "<notIncluded xml:lang='de'>"
            + "<notIncluded xml:lang='uk'>"
            + "<included                 >"
            + "</included>"
            + "</notIncluded>"
            + "</notIncluded>"
            + "</included>";

        String definedOutput = ""
            + "<included xml:lang=\"uk\">"
            + "<included xml:lang=\"uk\">"
            + "</included>"
            + "</included>";
        //J+
        assertTrue(doTestXMLAttributes(input, definedOutput));
    }

    /**
     * Method testXMLAttributes3
     */
    @org.junit.jupiter.api.Test
    public void testXMLAttributes3() throws Exception {
        //J-
        String input = ""
            + "<included xml:lang='de'>"
            + "<notIncluded xml:lang='de'>"
            + "<notIncluded xml:lang='uk'>"
            + "<included xml:lang='de'>"
            + "</included>"
            + "</notIncluded>"
            + "</notIncluded>"
            + "</included>";

        String definedOutput = ""
            + "<included xml:lang=\"de\">"
            + "<included xml:lang=\"de\">"
            + "</included>"
            + "</included>";
        //J+
        assertTrue(doTestXMLAttributes(input, definedOutput));
    }

    /**
     * Method testXMLAttributes4
     */
    @org.junit.jupiter.api.Test
    @org.junit.jupiter.api.Disabled
    public void _testXMLAttributes4() throws Exception {
        //J-
        String input = ""
            + "<included xml:lang='de'>"
            + "<included xml:lang='de'>"
            + "<notIncluded xml:lang='uk'>"
            + "<included                 >"
            + "</included>"
            + "</notIncluded>"
            + "</included>"
            + "</included>";

        String definedOutput = ""
            + "<included xml:lang=\"de\">"
            + "<included>"
            + "<included xml:lang=\"uk\">"
            + "</included>"
            + "</included>"
            + "</included>";
        //J+
        assertTrue(doTestXMLAttributes(input, definedOutput));
    }

    /**
     * Method testXMLAttributes5
     */
    @org.junit.jupiter.api.Test
    @org.junit.jupiter.api.Disabled
    public void _testXMLAttributes5() throws Exception {
        //J-
        String input = ""
            + "<included xml:lang='de'>"
            + "<included xml:lang='de'>"
            + "<notIncluded xml:space='preserve' xml:lang='uk'>"
            + "<included                 >"
            + "</included>"
            + "</notIncluded>"
            + "</included>"
            + "</included>";

        String definedOutput = ""
            + "<included xml:lang=\"de\">"
            + "<included>"
            + "<included xml:lang=\"uk\" xml:space=\"preserve\">"
            + "</included>"
            + "</included>"
            + "</included>";
        //J+
        assertTrue(doTestXMLAttributes(input, definedOutput));
    }

    /**
     * Method testXMLAttributes6
     */
    @org.junit.jupiter.api.Test
    @org.junit.jupiter.api.Disabled
    public void _testXMLAttributes6() throws Exception {
        //J-
        String input = ""
            + "<included xml:space='preserve'  xml:lang='de'>"
            + "<included xml:lang='de'>"
            + "<notIncluded xml:lang='uk'>"
            + "<included>"
            + "</included>"
            + "</notIncluded>"
            + "</included>"
            + "</included>";

        String definedOutput = ""
            + "<included xml:lang=\"de\" xml:space=\"preserve\">"
            + "<included>"
            + "<included xml:lang=\"uk\" xml:space=\"preserve\">"
            + "</included>"
            + "</included>"
            + "</included>";
        //J+
        assertTrue(doTestXMLAttributes(input, definedOutput));
    }

    /**
     * Method doTestXMLAttributes
     *
     * @param input
     * @param definedOutput
     * @param writeResultsToFile
     */
    private boolean doTestXMLAttributes(String input, String definedOutput) throws Exception {

        Document doc = null;
        try (InputStream is = new ByteArrayInputStream(input.getBytes())) {
            doc = XMLUtils.read(is, true);
        }
        Canonicalizer c14nizer =
            Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);

        //XMLUtils.circumventBug2650(doc);

        XPathFactory xpf = XPathFactory.newInstance();
        XPath xPath = xpf.newXPath();
        xPath.setNamespaceContext(new DSNamespaceContext());

        String xpath =
            "(//*[local-name()='included'] | //@*[parent::node()[local-name()='included']])";
        NodeList nodes =
            (NodeList)xPath.evaluate(xpath, doc, XPathConstants.NODESET);

        byte[] result = c14nizer.canonicalizeXPathNodeSet(nodes);
        byte[] defined = definedOutput.getBytes();
        assertEquals(definedOutput, new String(result));
        return java.security.MessageDigest.isEqual(defined, result);
    }

    private boolean c14nAndCompare(
                                   String fileIn,
                                   String fileRef,
                                   String fileOut,
                                   String c14nURI,
                                   String xpath
                               ) throws Exception {
        Map<String, String> namespace = new HashMap<>();
        return c14nAndCompare(fileIn, fileRef, fileOut,
            c14nURI, xpath, namespace);
    }

    private boolean c14nAndCompare(
        String fileIn,
        String fileRef,
        String fileOut,
        String c14nURI,
        String xpath,
        Map<String, String> namespaces
    ) throws Exception {

        Document doc = XMLUtils.read(fileIn, false);


        Canonicalizer c14n = Canonicalizer.getInstance(c14nURI);
        byte[] c14nBytes = null;

        if (xpath == null) {
            c14nBytes = c14n.canonicalizeSubtree(doc);
        } else {
            NodeList nl = null;

            XPathFactory xpf = XPathFactory.newInstance();
            XPath xPath = xpf.newXPath();
            DSNamespaceContext namespaceContext =
                new DSNamespaceContext(namespaces);
            xPath.setNamespaceContext(namespaceContext);

            nl = (NodeList)xPath.evaluate(xpath, doc, XPathConstants.NODESET);

            c14nBytes = c14n.canonicalizeXPathNodeSet(nl);
        }

        // org.xml.sax.InputSource refIs = resolver.resolveEntity(null, fileRef);
        // byte[] refBytes = JavaUtils.getBytesFromStream(refIs.getByteStream());
        byte[] refBytes = JavaUtils.getBytesFromFile(fileRef);

        // if everything is OK, result is true; we do a binary compare, byte by byte
        boolean result = java.security.MessageDigest.isEqual(refBytes, c14nBytes);

        if (!result) {
            File f = new File(fileOut);
            if (!f.exists()) {
                File parent = new File(f.getParent());
                parent.mkdirs();
                f.createNewFile();
            }
            FileOutputStream fos = new FileOutputStream(f);

            fos.write(c14nBytes);
            LOG.debug("Wrote erroneous result to file " + f.toURI().toURL().toString());
            assertEquals(new String(refBytes),new String(c14nBytes));
            fos.close();
        }

        return result;
    }

    /**
     * This method takes the input bytes as XML Document and converts it to an
     * UTF-16 encoded XML document which is serialized to byte[] and returned.
     *
     * @param input
     */
    public static byte[] convertToUTF16(byte[] input) throws Exception {
        //String ENCODING_ISO8859_1 = "ISO-8859-1";
        //String ENCODING_UTF8 = java.nio.charset.StandardCharsets.UTF_8;
        String ENCODING_UTF16 = "UTF-16";
        Document doc = null;
        try (InputStream is = new ByteArrayInputStream(input)) {
            doc = XMLUtils.read(is, false);
        }
        TransformerFactory tFactory = TransformerFactory.newInstance();
        Transformer transformer = tFactory.newTransformer();

        transformer.setOutputProperty(OutputKeys.ENCODING, ENCODING_UTF16);
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");

        DOMSource source = new DOMSource(doc);
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        StreamResult result = new StreamResult(os);

        transformer.transform(source, result);

        return os.toByteArray();
    }

}