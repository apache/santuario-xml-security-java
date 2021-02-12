package org.apache.xml.security.stax.ext;

import javax.xml.namespace.QName;

import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.stax.XMLSecStartElementImpl;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;

public class NoElementSelectorTest {

    @Test
    public void testSelection() {
        NoElementSelector elementSelector = NoElementSelector.getInstance();
        OutputProcessorChain context = mock(OutputProcessorChain.class);
        assertThat(elementSelector.select(null, context), is(false));
        XMLSecStartElement element = new XMLSecStartElementImpl(new QName("element"), null, null);
        assertThat(elementSelector.select(element, context), is(false));
    }

    @Test
    public void testStringValue() {
        assertThat(NoElementSelector.getInstance().toString(), is(equalTo("")));
    }
}