package org.apache.xml.security.stax.ext;

import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;

/**
 * Selects the document element (the {@code null} element).
 * Use this selector to secure parts that are not specific to a certain element, but rather apply to the document as a
 * whole, such as a secure part that has an external reference.
 * This is equivalent to {@link SecurePart#setExternalReference(String)}.
 */
public class DocumentElementSelector implements ElementSelector {

    private static class LazilyInitialized {

        @SuppressWarnings("PMD.AccessorClassGeneration")
        private static final DocumentElementSelector INSTANCE = new DocumentElementSelector();
    }

    private DocumentElementSelector() {
    }

    @Override
    public boolean select(XMLSecStartElement element, OutputProcessorChain outputProcessorChain) {
        return element == null;
    }

    @Override
    public String toString() {
        return "/";
    }

    public static DocumentElementSelector getInstance() {
        return LazilyInitialized.INSTANCE;
    }
}
