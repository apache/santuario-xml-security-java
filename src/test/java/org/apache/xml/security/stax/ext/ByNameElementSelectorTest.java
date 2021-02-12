package org.apache.xml.security.stax.ext;

import javax.xml.namespace.QName;

import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.stax.XMLSecStartElementImpl;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

public class ByNameElementSelectorTest {

    @Test
    public void testConstructionThrowsWhenNameIsNull() {
        assertThrows(NullPointerException.class, () -> new ByNameElementSelector(null));
    }

    @Test
    public void testSelection() {
        QName name = new QName("element");
        ByNameElementSelector elementSelector = new ByNameElementSelector(name);
        OutputProcessorChain context = mock(OutputProcessorChain.class);
        assertThat(elementSelector.select(null, context), is(false));
        XMLSecStartElement element = new XMLSecStartElementImpl(name, null, null);
        assertThat(elementSelector.select(element, context), is(true));
        XMLSecStartElement anotherElement = new XMLSecStartElementImpl(new QName("urn:test:ns", "element"), null, null);
        assertThat(elementSelector.select(anotherElement, context), is(false));
    }

    @Test
    public void testStringValue() {
        assertThat(new ByNameElementSelector(new QName("element")).toString(), is(equalTo("//element")));
        assertThat(new ByNameElementSelector(new QName("urn:test:ns", "element")).toString(), is(equalTo("//{urn:test:ns}element")));
        assertThat(new ByNameElementSelector(new QName(null, "element", "pf")).toString(), is(equalTo("//element")));
        assertThat(new ByNameElementSelector(new QName("urn:test:ns0", "element", "pf0")).toString(), is(equalTo("//{urn:test:ns0}element")));
    }
}