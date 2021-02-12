package org.apache.xml.security.stax.ext;

import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;

/**
 * Selects the root element as the element to secure.
 * This replaces {@link SecurePart#setSecureEntireRequest(boolean)}.
 */
public class RootElementSelector implements ElementSelector {

    private static final class LazilyInitialized {

        @SuppressWarnings("PMD.AccessorClassGeneration")
        private static final RootElementSelector INSTANCE = new RootElementSelector();
    }

    private RootElementSelector() {
    }

    @Override
    public boolean select(XMLSecStartElement element, OutputProcessorChain outputProcessorChain) {
        return element != null && element.getParentXMLSecStartElement() == null;
    }

    @Override
    public String toString() {
        return "/*";
    }

    public static RootElementSelector getInstance() {
        return LazilyInitialized.INSTANCE;
    }
}
