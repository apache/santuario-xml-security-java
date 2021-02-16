package org.apache.xml.security.test.stax.utils;

import java.io.StringReader;
import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecNamespace;
import org.apache.xml.security.utils.KeyValue;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

import static org.apache.xml.security.test.stax.utils.TestUtils.convertNodeToAttributesAndNamespaces;
import static org.apache.xml.security.test.stax.utils.TestUtils.convertNodeToQName;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

public class TestUtilsTest {

    @Test
    public void testConvertNodeToAttributesAndNamespace() throws Exception {
        String xml = "<prefix:localPart xmlns:prefix='urn:test:ns' prefix:attr1='val1' xmlns='urn:test:default-ns' attr2='val2'/>";
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        Document document = documentBuilderFactory.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
        Node node = document.getFirstChild();
        QName name = convertNodeToQName(node);
        assertThat(name.getLocalPart(), is(equalTo("localPart")));
        assertThat(name.getNamespaceURI(), is(equalTo("urn:test:ns")));
        assertThat(name.getPrefix(), is(equalTo("prefix")));
        KeyValue<List<XMLSecAttribute>, List<XMLSecNamespace>> attributesAndNamespaces = convertNodeToAttributesAndNamespaces(node);
        List<XMLSecAttribute> attributes = attributesAndNamespaces.getKey();
        List<XMLSecNamespace> namespaces = attributesAndNamespaces.getValue();
        assertThat(namespaces.size(), is(2));
        int namespaceIndex1 = 0;
        for (XMLSecNamespace namespace : namespaces) {
            if (namespace.getPrefix().equals("prefix")) {
                break;
            }
            namespaceIndex1++;
        }
        int namespaceIndex2 = (namespaceIndex1 + 1) % namespaces.size();
        XMLSecNamespace namespace1 = namespaces.get(namespaceIndex1);
        assertThat(namespace1.getPrefix(), is(equalTo("prefix")));
        assertThat(namespace1.getNamespaceURI(), is(equalTo("urn:test:ns")));
        assertThat(namespace1.isDefaultNamespaceDeclaration(), is(false));
        XMLSecNamespace namespace2 = namespaces.get(namespaceIndex2);
        assertThat(namespace2.getPrefix(), is(equalTo(XMLConstants.DEFAULT_NS_PREFIX)));
        assertThat(namespace2.getNamespaceURI(), is(equalTo("urn:test:default-ns")));
        assertThat(namespace2.isDefaultNamespaceDeclaration(), is(true));
        assertThat(attributes.size(), is(2));
        int attrIndex1 = 0;
        for (XMLSecAttribute attribute : attributes) {
            if (attribute.getValue().equals("val1")) {
                break;
            }
            attrIndex1++;
        }
        int attrIndex2 = (attrIndex1 + 1) % attributes.size();
        XMLSecAttribute attr1 = attributes.get(attrIndex1);
        assertThat(attr1.getAttributeNamespace(), is(equalTo(namespace1)));
        assertThat(attr1.getName().getLocalPart(), is(equalTo("attr1")));
        assertThat(attr1.getName().getNamespaceURI(), is(equalTo("urn:test:ns")));
        assertThat(attr1.getValue(), is(equalTo("val1")));
        XMLSecAttribute attr2 = attributes.get(attrIndex2);
        assertThat(attr2.getAttributeNamespace(), is(equalTo(namespace2)));
        assertThat(attr2.getName().getLocalPart(), is(equalTo("attr2")));
        assertThat(attr2.getName().getNamespaceURI(), is(equalTo(XMLConstants.NULL_NS_URI)));
        assertThat(attr2.getValue(), is(equalTo("val2")));
    }
}
