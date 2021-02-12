package org.apache.xml.security.stax.ext;

import javax.xml.namespace.QName;

import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;

import static java.util.Objects.requireNonNull;

/**
 * Selects elements to secure by element name.
 * This is equivalent to {@link SecurePart#setName(QName)}.
 */
public class ByNameElementSelector implements ElementSelector {

    private final QName name;

    public ByNameElementSelector(QName name) {
        requireNonNull(name, "name is null");
        this.name = name;
    }

    @Override
    public boolean select(XMLSecStartElement element, OutputProcessorChain outputProcessorChain) {
        return element != null && element.getName().equals(name);
    }

    @Override
    public String toString() {
        return "//" + name;
    }
}
