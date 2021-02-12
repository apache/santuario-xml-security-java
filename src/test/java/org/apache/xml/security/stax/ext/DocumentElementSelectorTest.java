package org.apache.xml.security.stax.ext;

import javax.xml.namespace.QName;

import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.stax.XMLSecStartElementImpl;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;

public class DocumentElementSelectorTest {

    @Test
    public void testSelection() {
        DocumentElementSelector selector = DocumentElementSelector.getInstance();
        OutputProcessorChain context = mock(OutputProcessorChain.class);
        assertThat(selector.select(null, context), is(true));
        XMLSecStartElement element = new XMLSecStartElementImpl(new QName("root"), null, null);
        assertThat(selector.select(element, context), is(false));
    }

    @Test
    public void testStringValue() {
        assertThat(DocumentElementSelector.getInstance().toString(), is(equalTo("/")));
    }
}