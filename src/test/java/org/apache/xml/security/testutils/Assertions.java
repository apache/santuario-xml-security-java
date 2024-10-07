package org.apache.xml.security.testutils;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * {@code Assertions} is a collection of utility methods that support asserting
 * conditions in DOM structure testing.
 *
 */
public class Assertions {

    /**
     * Asserts that document contains the expected number of nodes for the given XPaths.
     * @param resultDocument the document to assert if it contains the expected number of nodes
     * @param assertNodeCountByXPaths the map of XPaths as key  and the expected number of nodes as map value
     * @throws XPathExpressionException if an error occurs while evaluating the XPath expression
     * @throws AssertionError if the number of nodes for the given XPath does not match the expected number of nodes
     */
    public static void assertNodeCountForXPath(Document resultDocument, Map<String, String> assertNodeCountByXPaths) throws XPathExpressionException {

        for (Map.Entry<String, String> entry : assertNodeCountByXPaths.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();
            assertNodeCountForXPath(resultDocument, key, Integer.parseInt(value));
        }
    }

    //Method asserts that given XPATH returns the expected number of nodes

    /**
     * Asserts that the given document contains the expected number of nodes for the given XPath.
     * @param doc the document to assert if it contains the expected number of nodes
     * @param xpath the XPath string expression to evaluate
     * @param expectedCount the expected number of nodes for the given XPath
     * @throws XPathExpressionException if an error occurs while evaluating the XPath expression
     * @throws AssertionError if the number of nodes for the given XPath does not match the expected number of nodes
     */
    public static void assertNodeCountForXPath(Document doc, String xpath, int expectedCount) throws XPathExpressionException {
        XPath xPath = XPathFactory.newInstance().newXPath();
        NodeList nodes = (NodeList) xPath.evaluate(xpath, doc, XPathConstants.NODESET);
        assertEquals(expectedCount, nodes.getLength(), "Node count for xpath [" + xpath + "] does not match");
    }
}
