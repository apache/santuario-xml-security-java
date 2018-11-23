/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.xml.security.staxutils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Stack;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.stream.Location;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLResolver;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.Source;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.sax.SAXSource;
import javax.xml.transform.stax.StAXSource;
import javax.xml.transform.stream.StreamSource;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.UserDataHandler;
import org.xml.sax.InputSource;

public final class StaxUtils {

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(StaxUtils.class);

    private static final String XML_NS = "http://www.w3.org/2000/xmlns/";

    private static final BlockingQueue<XMLInputFactory> DISALLOW_DOCTYPE_INPUT_FACTORY_POOL = new ArrayBlockingQueue<>(20);
    private static final BlockingQueue<XMLInputFactory> ALLOW_DOCTYPE_INPUT_FACTORY_POOL = new ArrayBlockingQueue<>(20);

    private StaxUtils() {
    }

    /**
     * Return a cached, namespace-aware, factory.
     */
    private static XMLInputFactory getXMLInputFactory(boolean disAllowDocTypeDeclarations) {
        XMLInputFactory f = disAllowDocTypeDeclarations
            ? DISALLOW_DOCTYPE_INPUT_FACTORY_POOL.poll() : ALLOW_DOCTYPE_INPUT_FACTORY_POOL.poll();
        if (f == null) {
            f = createXMLInputFactory(disAllowDocTypeDeclarations);
        }
        return f;
    }

    private static void returnXMLInputFactory(XMLInputFactory factory, boolean disAllowDocTypeDeclarations) {
        if (disAllowDocTypeDeclarations) {
            DISALLOW_DOCTYPE_INPUT_FACTORY_POOL.offer(factory);
        } else {
            ALLOW_DOCTYPE_INPUT_FACTORY_POOL.offer(factory);
        }
    }

    /**
     * Return a new factory so that the caller can set sticky parameters.
     * @param disAllowDocTypeDeclarations
     * @throws XMLStreamException
     */
    private static XMLInputFactory createXMLInputFactory(boolean disAllowDocTypeDeclarations) {
        XMLInputFactory factory = null;
        try {
            factory = XMLInputFactory.newInstance();
        } catch (Throwable t) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("XMLInputFactory.newInstance() failed with: ", t);
            }
            throw new RuntimeException("Failed to create XMLInputFactory.");
        }

        setProperty(factory, XMLInputFactory.IS_NAMESPACE_AWARE, true);

        if (disAllowDocTypeDeclarations) {
            setProperty(factory, XMLInputFactory.SUPPORT_DTD, Boolean.FALSE);
            setProperty(factory, XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, Boolean.FALSE);
            setProperty(factory, XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE);
            factory.setXMLResolver(new XMLResolver() {
                public Object resolveEntity(String publicID, String systemID,
                                            String baseURI, String namespace)
                    throws XMLStreamException {
                    throw new XMLStreamException("Reading external entities is disabled");
                }
            });
        }

        return factory;
    }

    private static boolean setProperty(XMLInputFactory f, String p, Object o) {
        try {
            f.setProperty(p,  o);
            return true;
        } catch (Throwable t) {
            //ignore
        }
        return false;
    }

    public static Document read(Source s, boolean disAllowDocTypeDeclarations) throws XMLStreamException {
        XMLStreamReader reader = createXMLStreamReader(s, disAllowDocTypeDeclarations);
        try {
            return read(reader);
        } finally {
            try {
                reader.close();
            } catch (Exception ex) {
                //ignore
            }
        }
    }
    public static Document read(InputStream s, boolean disAllowDocTypeDeclarations) throws XMLStreamException {
        XMLStreamReader reader = createXMLStreamReader(s, disAllowDocTypeDeclarations);
        try {
            return read(reader);
        } finally {
            try {
                reader.close();
            } catch (Exception ex) {
                //ignore
            }
        }
    }
    public static Document read(Reader s, boolean disAllowDocTypeDeclarations) throws XMLStreamException {
        XMLStreamReader reader = createXMLStreamReader(s, disAllowDocTypeDeclarations);
        try {
            return read(reader);
        } finally {
            try {
                reader.close();
            } catch (Exception ex) {
                //ignore
            }
        }
    }
    public static Document read(File is, boolean disAllowDocTypeDeclarations) throws XMLStreamException, IOException {
        try (InputStream fin = Files.newInputStream(is.toPath())) {
            return read(fin, disAllowDocTypeDeclarations);
        }
    }
    public static Document read(InputSource s, boolean disAllowDocTypeDeclarations) throws XMLStreamException {
        XMLStreamReader reader = createXMLStreamReader(s, disAllowDocTypeDeclarations);
        try {
            return read(reader);
        } finally {
            try {
                reader.close();
            } catch (Exception ex) {
                //ignore
            }
        }
    }
    public static Document read(XMLStreamReader reader) throws XMLStreamException {
        return read(reader, false);
    }
    public static Document read(XMLStreamReader reader, boolean recordLoc) throws XMLStreamException {
        Document doc = DOMUtils.newDocument(true);
        if (reader.getLocation().getSystemId() != null) {
            try {
                doc.setDocumentURI(reader.getLocation().getSystemId());
            } catch (Exception e) {
                //ignore - probably not DOM level 3
            }
        }
        readDocElements(doc, doc, reader, true, recordLoc);
        return doc;
    }

    public static Document read(DocumentBuilder builder, XMLStreamReader reader, boolean repairing)
        throws XMLStreamException {

        Document doc = builder == null ? DOMUtils.newDocument(true) : builder.newDocument();
        if (reader.getLocation().getSystemId() != null) {
            try {
                doc.setDocumentURI(reader.getLocation().getSystemId());
            } catch (Exception e) {
                //ignore - probably not DOM level 3
            }
        }
        readDocElements(doc, reader, repairing);
        return doc;
    }

    /**
     * @param parent
     */
    private static Document getDocument(Node parent) {
        return parent instanceof Document ? (Document)parent : parent.getOwnerDocument();
    }

    private static boolean isDeclared(Element e, String namespaceURI, String prefix) {
        while (e != null) {
            Attr att;
            if (prefix != null && prefix.length() > 0) {
                att = e.getAttributeNodeNS(XML_NS, prefix);
            } else {
                att = e.getAttributeNode("xmlns");
            }

            if (att != null && att.getNodeValue().equals(namespaceURI)) {
                return true;
            }

            if (e.getParentNode() instanceof Element) {
                e = (Element)e.getParentNode();
            } else if (isEmpty(prefix) && isEmpty(namespaceURI)) {
                //A document that probably doesn't have any namespace qualifies elements
                return true;
            } else {
                e = null;
            }
        }
        return false;
    }

    public static void readDocElements(Node parent, XMLStreamReader reader, boolean repairing)
        throws XMLStreamException {
        Document doc = getDocument(parent);
        readDocElements(doc, parent, reader, repairing, false);
    }

    public static void readDocElements(Node parent, XMLStreamReader reader, boolean repairing,
                                       boolean isThreshold)
        throws XMLStreamException {
        Document doc = getDocument(parent);
        readDocElements(doc, parent, reader, repairing, false, isThreshold);
    }

    /**
     * @param parent
     * @param reader
     * @throws XMLStreamException
     */
    public static void readDocElements(Document doc, Node parent,
                                       XMLStreamReader reader, boolean repairing, boolean recordLoc)
        throws XMLStreamException {
        readDocElements(doc, parent, reader, repairing, recordLoc, false);
    }

    /**
     * @param parent
     * @param reader
     * @throws XMLStreamException
     */
    public static void readDocElements(Document doc, Node parent,
                                       XMLStreamReader reader, boolean repairing, boolean recordLoc,
                                       boolean isThreshold)
        throws XMLStreamException {
        Stack<Node> stack = new Stack<Node>();
        int event = reader.getEventType();
        while (reader.hasNext()) {
            switch (event) {
            case XMLStreamConstants.START_ELEMENT: {
                Element e;
                if (!isEmpty(reader.getPrefix())) {
                    e = doc.createElementNS(reader.getNamespaceURI(),
                                            reader.getPrefix() + ":" + reader.getLocalName());
                } else {
                    e = doc.createElementNS(reader.getNamespaceURI(), reader.getLocalName());
                }
                e = (Element)parent.appendChild(e);
                recordLoc = addLocation(doc, e, reader, recordLoc);

                for (int ns = 0; ns < reader.getNamespaceCount(); ns++) {
                    String uri = reader.getNamespaceURI(ns);
                    String prefix = reader.getNamespacePrefix(ns);

                    declare(e, uri, prefix);
                }

                for (int att = 0; att < reader.getAttributeCount(); att++) {
                    String name = reader.getAttributeLocalName(att);
                    String prefix = reader.getAttributePrefix(att);
                    if (prefix != null && prefix.length() > 0) {
                        name = prefix + ":" + name;
                    }

                    Attr attr = doc.createAttributeNS(reader.getAttributeNamespace(att), name);
                    attr.setValue(reader.getAttributeValue(att));
                    e.setAttributeNode(attr);
                }

                if (repairing && !isDeclared(e, reader.getNamespaceURI(), reader.getPrefix())) {
                    declare(e, reader.getNamespaceURI(), reader.getPrefix());
                }
                stack.push(parent);
                parent = e;
                break;
            }
            case XMLStreamConstants.END_ELEMENT:
                if (stack.isEmpty()) {
                    return;
                }
                parent = stack.pop();
                //if (parent instanceof Document || parent instanceof DocumentFragment) {
                //    return;
                //}
                break;
            case XMLStreamConstants.NAMESPACE:
                break;
            case XMLStreamConstants.ATTRIBUTE:
                break;
            case XMLStreamConstants.CHARACTERS:
                if (parent != null) {
                    recordLoc = addLocation(doc,
                                            parent.appendChild(doc.createTextNode(reader.getText())),
                                            reader, recordLoc);
                }
                break;
            case XMLStreamConstants.COMMENT:
                if (parent != null) {
                    parent.appendChild(doc.createComment(reader.getText()));
                }
                break;
            case XMLStreamConstants.CDATA:
                recordLoc = addLocation(doc,
                                        parent.appendChild(doc.createCDATASection(reader.getText())),
                                        reader, recordLoc);
                break;
            case XMLStreamConstants.PROCESSING_INSTRUCTION:
                parent.appendChild(doc.createProcessingInstruction(reader.getPITarget(), reader.getPIData()));
                break;
            case XMLStreamConstants.ENTITY_REFERENCE:
                parent.appendChild(doc.createProcessingInstruction(reader.getPITarget(), reader.getPIData()));
                break;
            default:
                break;
            }

            if (reader.hasNext()) {
                event = reader.next();
            }
        }
    }

    private static boolean addLocation(Document doc, Node node,
                                       Location loc,
                                       boolean recordLoc) {
        if (recordLoc && loc != null && (loc.getColumnNumber() != 0 || loc.getLineNumber() != 0)) {
            try {
                final int charOffset = loc.getCharacterOffset();
                final int colNum = loc.getColumnNumber();
                final int linNum = loc.getLineNumber();
                final String pubId = loc.getPublicId() == null ? doc.getDocumentURI() : loc.getPublicId();
                final String sysId = loc.getSystemId() == null ? doc.getDocumentURI() : loc.getSystemId();
                Location loc2 = new Location() {
                    public int getCharacterOffset() {
                        return charOffset;
                    }
                    public int getColumnNumber() {
                        return colNum;
                    }
                    public int getLineNumber() {
                        return linNum;
                    }
                    public String getPublicId() {
                        return pubId;
                    }
                    public String getSystemId() {
                        return sysId;
                    }
                };
                node.setUserData("location", loc2, LocationUserDataHandler.INSTANCE);
            } catch (Throwable ex) {
                //possibly not DOM level 3, won't be able to record this then
                return false;
            }
        }
        return recordLoc;
    }

    private static boolean addLocation(Document doc, Node node,
                                    XMLStreamReader reader,
                                    boolean recordLoc) {
        return addLocation(doc, node, reader.getLocation(), recordLoc);
    }

    private static class LocationUserDataHandler implements UserDataHandler {
        public static final LocationUserDataHandler INSTANCE = new LocationUserDataHandler();

        public void handle(short operation, String key, Object data, Node src, Node dst) {
            if (operation == NODE_CLONED) {
                dst.setUserData(key, data, this);
            }
        }
    }

    private static void declare(Element node, String uri, String prefix) {
        String qualname;
        if (prefix != null && prefix.length() > 0) {
            qualname = "xmlns:" + prefix;
        } else {
            qualname = "xmlns";
        }
        Attr attr = node.getOwnerDocument().createAttributeNS(XML_NS, qualname);
        attr.setValue(uri);
        node.setAttributeNodeNS(attr);
    }

    public static XMLStreamReader createXMLStreamReader(InputSource src, boolean disAllowDocTypeDeclarations) {
        String sysId = src.getSystemId() == null ? null : src.getSystemId();
        String pubId = src.getPublicId() == null ? null : src.getPublicId();
        if (src.getByteStream() != null) {
            if (src.getEncoding() == null) {
                StreamSource ss = new StreamSource(src.getByteStream(), sysId);
                ss.setPublicId(pubId);
                return createXMLStreamReader(ss, disAllowDocTypeDeclarations);
            }
            return createXMLStreamReader(src.getByteStream(), src.getEncoding(), disAllowDocTypeDeclarations);
        } else if (src.getCharacterStream() != null) {
            StreamSource ss = new StreamSource(src.getCharacterStream(), sysId);
            ss.setPublicId(pubId);
            return createXMLStreamReader(ss, disAllowDocTypeDeclarations);
        } else {
            try {
                URL url = new URL(sysId);
                StreamSource ss = new StreamSource(url.openStream(), sysId);
                ss.setPublicId(pubId);
                return createXMLStreamReader(ss, disAllowDocTypeDeclarations);
            } catch (Exception ex) {
                //ignore - not a valid URL
            }
        }
        throw new IllegalArgumentException("InputSource must have a ByteStream or CharacterStream");
    }
    /**
     * @param in
     * @param encoding
     */
    public static XMLStreamReader createXMLStreamReader(InputStream in, String encoding, boolean disAllowDocTypeDeclarations) {
        if (encoding == null) {
            encoding = StandardCharsets.UTF_8.name();
        }

        XMLInputFactory factory = getXMLInputFactory(disAllowDocTypeDeclarations);
        try {
            return factory.createXMLStreamReader(in, encoding);
        } catch (XMLStreamException e) {
            throw new RuntimeException("Couldn't parse stream.", e);
        } finally {
            returnXMLInputFactory(factory, disAllowDocTypeDeclarations);
        }
    }

    /**
     * @param in
     */
    public static XMLStreamReader createXMLStreamReader(InputStream in, boolean disAllowDocTypeDeclarations) {
        XMLInputFactory factory = getXMLInputFactory(disAllowDocTypeDeclarations);
        try {
            return factory.createXMLStreamReader(in);
        } catch (XMLStreamException e) {
            throw new RuntimeException("Couldn't parse stream.", e);
        } finally {
            returnXMLInputFactory(factory, disAllowDocTypeDeclarations);
        }
    }
    public static XMLStreamReader createXMLStreamReader(String systemId, InputStream in, boolean disAllowDocTypeDeclarations) {
        XMLInputFactory factory = getXMLInputFactory(disAllowDocTypeDeclarations);
        try {
            return factory.createXMLStreamReader(systemId, in);
        } catch (XMLStreamException e) {
            throw new RuntimeException("Couldn't parse stream.", e);
        } finally {
            returnXMLInputFactory(factory, disAllowDocTypeDeclarations);
        }
    }

    public static XMLStreamReader createXMLStreamReader(Element el) {
        return new W3CDOMStreamReader(el);
    }
    public static XMLStreamReader createXMLStreamReader(Document doc) {
        return new W3CDOMStreamReader(doc.getDocumentElement());
    }
    public static XMLStreamReader createXMLStreamReader(Element el, String sysId) {
        return new W3CDOMStreamReader(el, sysId);
    }
    public static XMLStreamReader createXMLStreamReader(Document doc, String sysId) {
        return new W3CDOMStreamReader(doc.getDocumentElement(), sysId);
    }

    public static XMLStreamReader createXMLStreamReader(Source source, boolean disAllowDocTypeDeclarations) {
        try {
            if (source instanceof DOMSource) {
                DOMSource ds = (DOMSource)source;
                Node nd = ds.getNode();
                Element el = null;
                if (nd instanceof Document) {
                    el = ((Document)nd).getDocumentElement();
                } else if (nd instanceof Element) {
                    el = (Element)nd;
                }

                if (null != el) {
                    return new W3CDOMStreamReader(el, source.getSystemId());
                }
            } else if (source instanceof StAXSource) {
                return ((StAXSource)source).getXMLStreamReader();
            } else if (source instanceof SAXSource) {
                SAXSource ss = (SAXSource)source;
                if (ss.getXMLReader() == null) {
                    return createXMLStreamReader(((SAXSource)source).getInputSource(), disAllowDocTypeDeclarations);
                }
            }

            XMLInputFactory factory = getXMLInputFactory(disAllowDocTypeDeclarations);
            try {
                XMLStreamReader reader = null;

                try {
                    reader = factory.createXMLStreamReader(source);
                } catch (UnsupportedOperationException e) {
                    //ignore
                }
                if (reader == null && source instanceof StreamSource) {
                    //createXMLStreamReader from Source is optional, we'll try and map it
                    StreamSource ss = (StreamSource)source;
                    if (ss.getInputStream() != null) {
                        reader = factory.createXMLStreamReader(ss.getSystemId(),
                                                               ss.getInputStream());
                    } else {
                        reader = factory.createXMLStreamReader(ss.getSystemId(),
                                                               ss.getReader());
                    }
                }
                return reader;
            } finally {
                returnXMLInputFactory(factory, disAllowDocTypeDeclarations);
            }
        } catch (XMLStreamException e) {
            throw new RuntimeException("Couldn't parse stream.", e);
        }
    }

    /**
     * @param reader
     */
    public static XMLStreamReader createXMLStreamReader(Reader reader, boolean disAllowDocTypeDeclarations) {
        XMLInputFactory factory = getXMLInputFactory(disAllowDocTypeDeclarations);
        try {
            return factory.createXMLStreamReader(reader);
        } catch (XMLStreamException e) {
            throw new RuntimeException("Couldn't parse stream.", e);
        } finally {
            returnXMLInputFactory(factory, disAllowDocTypeDeclarations);
        }
    }

    private static boolean isEmpty(String str) {
        if (str != null) {
            int len = str.length();
            for (int x = 0; x < len; ++x) {
                if (str.charAt(x) > ' ') {
                    return false;
                }
            }
        }
        return true;
    }


}
