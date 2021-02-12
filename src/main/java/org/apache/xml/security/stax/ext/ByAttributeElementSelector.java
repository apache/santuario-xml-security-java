package org.apache.xml.security.stax.ext;

import java.util.function.Supplier;

import javax.xml.namespace.QName;
import javax.xml.stream.events.Attribute;

import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;

import static java.util.Objects.requireNonNull;

/**
 * Selects elements to secure based on a given attribute name and value.
 * This is equivalent to {@link SecurePart#setIdToSecure(String)} +
 * {@link XMLSecurityProperties#setIdAttributeNS(QName)}.
 */
public class ByAttributeElementSelector implements ElementSelector {

    private final Supplier<QName> nameSupplier;
    private final String value;

    ByAttributeElementSelector(Supplier<QName> nameSupplier, String value) {
        requireNonNull(value, "value is null");
        this.nameSupplier = nameSupplier;
        this.value = value;
    }

    public ByAttributeElementSelector(QName name, String value) {
        this(() -> name, value);
    }

    @Override
    public boolean select(XMLSecStartElement element, OutputProcessorChain outputProcessorChain) {
        if (element != null) {
            QName name = nameSupplier.get();
            if (name != null) {
                Attribute attribute = element.getAttributeByName(name);
                if (attribute != null && value.equals(attribute.getValue())) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public String toString() {
        return "//*[@" + nameSupplier.get() + "='" + value + "']";
    }
}
