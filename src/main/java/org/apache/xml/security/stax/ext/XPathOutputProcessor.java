package org.apache.xml.security.stax.ext;

import java.util.Iterator;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

class XPathOutputProcessor extends AbstractOutputProcessor {

    private final XPathModifier modifier;

    XPathOutputProcessor(XPathModifier modifier) {
        this.modifier = modifier;
    }

    XPathModifier getModifier() {
        return modifier;
    }

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        int eventType = xmlSecEvent.getEventType();
        if (eventType == XMLStreamConstants.START_ELEMENT) {
            descend(xmlSecEvent.asStartElement(), outputProcessorChain.getSecurityContext());
        } else if (eventType == XMLStreamConstants.END_ELEMENT) {
            ascend(outputProcessorChain.getSecurityContext());
        }
        outputProcessorChain.processEvent(xmlSecEvent);
    }

    private void descend(XMLSecStartElement startElement, OutboundSecurityContext securityContext) throws XMLStreamException {
        QName name = startElement.getName();
        Iterator<Attribute> attributes = startElement.getAttributes();
        Element element = securityContext.get(Element.class);
        Element newElement = null;
        if (modifier != null) {
            Node parent = element;
            Document document;
            if (parent != null) {
                document = parent.getOwnerDocument();
            } else {
                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                // Make sure we produce DOM level 3 nodes.
                factory.setNamespaceAware(true);
                // Disable anything we don't need.
                factory.setIgnoringComments(true);
                factory.setIgnoringElementContentWhitespace(true);
                factory.setValidating(false);
                try {
                    DocumentBuilder builder = factory.newDocumentBuilder();
                    document = builder.newDocument();
                    // To be consistent with DOM, the root element has the document as parent (rather than null).
                    parent = document;
                } catch (ParserConfigurationException e) {
                    throw new XMLStreamException(e);
                }
            }
            newElement = XMLUtils.convertQNameToElement(document, name);
            while (attributes.hasNext()) {
                Attribute attribute = attributes.next();
                XMLUtils.setAttributeNS(newElement, attribute);
            }
            if (modifier == XPathModifier.Node) {
                parent = document;
            }
            if (modifier != XPathModifier.Tree) {
                NodeList children = parent.getChildNodes();
                for (int i = 0, n = children.getLength(); i != n; i++) {
                    Node child = children.item(i);
                    parent.removeChild(child);
                }
            }
            parent.appendChild(newElement);
        }
        securityContext.put(Element.class, newElement);
    }

    private void ascend(OutboundSecurityContext securityContext) {
        Element element = securityContext.get(Element.class);
        if (element != null) {
            Node parent = element.getParentNode();
            if (parent != null && modifier != XPathModifier.Tree) {
                parent.removeChild(element);
            }
            element = parent != element.getOwnerDocument() ? (Element) parent : null;
            securityContext.put(Element.class, element);
        }
    }
}
