package org.apache.xml.security.stax.ext;

import javax.xml.namespace.QName;

import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.stax.XMLSecStartElementImpl;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.Mockito.mock;

public class RootElementSelectorTest {

    @Test
    public void testSelection() {
        RootElementSelector selector = RootElementSelector.getInstance();
        assertThat(selector, is(notNullValue()));
        OutputProcessorChain context = mock(OutputProcessorChain.class);
        assertThat(selector.select(null, context), is(false));
        XMLSecStartElement rootElement = new XMLSecStartElementImpl(new QName("root"), null, null);
        assertThat(selector.select(rootElement, context), is(true));
        XMLSecStartElement branchElement = new XMLSecStartElementImpl(new QName("branch"), null, null, rootElement);
        assertThat(selector.select(branchElement, context), is(false));
        XMLSecStartElement anotherRootElement = new XMLSecStartElementImpl(new QName("anotherRoot"), null, null);
        assertThat(selector.select(anotherRootElement, context), is(true));
    }

    @Test
    public void testStringValue() {
        assertThat(RootElementSelector.getInstance().toString(), is(equalTo("/*")));
    }
}