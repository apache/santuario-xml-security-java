package org.apache.xml.security.stax.ext;

import java.util.UUID;

import javax.xml.namespace.QName;

import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.stax.XMLSecStartElementImpl;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public class SecurePartSelectorTest {

    @Test
    public void testConstructionThrowsWhenElementSelectorIsNull() {
        assertThrows(NullPointerException.class, () -> new SecurePartSelector(null, mock(SecurePartFactory.class), -1));
    }

    @Test
    public void testConstructionThrowsWhenSecurePartFactoryIsNull() {
        assertThrows(NullPointerException.class, () -> new SecurePartSelector(mock(ElementSelector.class), null, -1));
    }

    @Test
    public void testSelectReturnsNullWhenNotSelected() {
        QName name = new QName("element");
        XMLSecStartElement element = new XMLSecStartElementImpl(name, null, null);
        OutputProcessorChain context = mock(OutputProcessorChain.class);
        ElementSelector elementSelector = mock(ElementSelector.class);
        when(elementSelector.select(element, context)).thenReturn(false);
        SecurePartFactory securePartFactory = mock(SecurePartFactory.class);

        SecurePartSelector securePartSelector = new SecurePartSelector(elementSelector, securePartFactory, -1);

        assertThat(securePartSelector.select(element, context), is(nullValue()));
        verify(securePartFactory, never()).createSecurePart(nullable(XMLSecStartElement.class), nullable(OutputProcessorChain.class));
    }

    @Test
    public void testSelectDelegatesToFactory() {
        QName name = new QName("element");
        XMLSecStartElement element = new XMLSecStartElementImpl(name, null, null);
        OutputProcessorChain context = mock(OutputProcessorChain.class);
        ElementSelector elementSelector = mock(ElementSelector.class);
        when(elementSelector.select(element, context)).thenReturn(true);
        SecurePartFactory securePartFactory = mock(SecurePartFactory.class);
        SecurePart securePart = new SecurePart(name, SecurePart.Modifier.Element);
        when(securePartFactory.createSecurePart(element, context)).thenReturn(securePart);

        SecurePartSelector securePartSelector = new SecurePartSelector(elementSelector, securePartFactory, -1);

        assertThat(securePartSelector.select(element, context), is(securePart));
        verify(securePartFactory).createSecurePart(element, context);
        verifyNoMoreInteractions(securePartFactory);
    }

    @Test
    public void testStringValue() {
        ElementSelector elementSelector = mock(ElementSelector.class);
        String elementSelectorStringValue = UUID.randomUUID().toString();
        when(elementSelector.toString()).thenReturn(elementSelectorStringValue);
        SecurePartFactory securePartFactory = mock(SecurePartFactory.class);
        String securePartStringValue = UUID.randomUUID().toString();
        when(securePartFactory.toString()).thenReturn(securePartStringValue);

        SecurePartSelector securePartSelector = new SecurePartSelector(elementSelector, securePartFactory, -1);

        assertThat(securePartSelector.toString(), is(equalTo(elementSelectorStringValue + " # -1 -> " + securePartStringValue)));
    }

    @Test
    public void testRequiredNumOccurrences() {
        ElementSelector elementSelector = mock(ElementSelector.class);
        SecurePartFactory securePartFactory = mock(SecurePartFactory.class);

        SecurePartSelector securePartSelector = new SecurePartSelector(elementSelector, securePartFactory, 2);

        assertThat(securePartSelector.getRequiredNumOccurrences(), is(2));
    }
}