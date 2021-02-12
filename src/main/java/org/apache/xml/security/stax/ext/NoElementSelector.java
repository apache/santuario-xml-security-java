package org.apache.xml.security.stax.ext;

import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;

/**
 * An element selector that selects no elements.
 */
public class NoElementSelector implements ElementSelector {

    private static class LazilyInitialized {

        @SuppressWarnings("PMD.AccessorClassGeneration")
        private static final NoElementSelector INSTANCE = new NoElementSelector();
    }

    private NoElementSelector() {
    }

    @Override
    public boolean select(XMLSecStartElement element, OutputProcessorChain outputProcessorChain) {
        return false;
    }

    @Override
    public String toString() {
        return "";
    }

    public static NoElementSelector getInstance() {
        return LazilyInitialized.INSTANCE;
    }
}
