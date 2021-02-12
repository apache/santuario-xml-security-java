package org.apache.xml.security.stax.ext;

import java.util.List;

import javax.xml.namespace.QName;

import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.stax.XMLSecAttributeImpl;
import org.apache.xml.security.stax.impl.stax.XMLSecStartElementImpl;
import org.junit.jupiter.api.Test;

import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

public class ByAttributeElementSelectorTest {

    @Test
    public void testConstructionThrowsWhenValueIsNull() {
        assertThrows(NullPointerException.class, () -> new ByAttributeElementSelector(new QName("attr1"), null));
    }

    @Test
    public void testSelection() {
        QName attributeName = new QName("attr1");
        String value = "val1";
        ByAttributeElementSelector elementSelector = new ByAttributeElementSelector(attributeName, value);
        OutputProcessorChain context = mock(OutputProcessorChain.class);
        assertThat(elementSelector.select(null, context), is(false));

        QName elementName = new QName("element");
        List<XMLSecAttribute> attributes1 = asList(new XMLSecAttributeImpl(attributeName, "val1"));
        XMLSecStartElement element1 = new XMLSecStartElementImpl(elementName, attributes1, null);
        assertThat(elementSelector.select(element1, context), is(true));

        List<XMLSecAttribute> attributes2 = asList(new XMLSecAttributeImpl(attributeName, "val2"));
        XMLSecStartElement element2 = new XMLSecStartElementImpl(elementName, attributes2, null);
        assertThat(elementSelector.select(element2, context), is(false));

        QName attributeName2 = new QName("attr2");
        List<XMLSecAttribute> attributes3 = asList(new XMLSecAttributeImpl(attributeName2, "val1"));
        XMLSecStartElement element3 = new XMLSecStartElementImpl(elementName, attributes3, null);
        assertThat(elementSelector.select(element3, context), is(false));
    }

    @Test
    public void testStringValue() {
        assertThat(new ByAttributeElementSelector(new QName("attr1"), "val1").toString(), is(equalTo("//*[@attr1='val1']")));
        assertThat(new ByAttributeElementSelector(new QName("urn:test:ns", "attr1"), "val1").toString(), is(equalTo("//*[@{urn:test:ns}attr1='val1']")));
        assertThat(new ByAttributeElementSelector(new QName(null, "attr1", "pf1"), "val1").toString(), is(equalTo("//*[@attr1='val1']")));
        assertThat(new ByAttributeElementSelector(new QName("urn:test:ns", "attr1", "pf1"), "val1").toString(), is(equalTo("//*[@{urn:test:ns}attr1='val1']")));
    }
}