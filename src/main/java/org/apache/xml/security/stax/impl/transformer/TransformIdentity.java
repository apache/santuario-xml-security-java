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
package org.apache.xml.security.stax.impl.transformer;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;

import javax.xml.stream.XMLEventWriter;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.Transformer;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityUtils;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.processor.input.XMLEventReaderInputProcessor;
import org.apache.xml.security.utils.UnsyncByteArrayInputStream;
import org.apache.xml.security.utils.UnsyncByteArrayOutputStream;

/**
 */
public class TransformIdentity implements Transformer {

    private static XMLOutputFactory xmlOutputFactory;
    private static XMLInputFactory xmlInputFactory;
    private OutputStream outputStream;
    private XMLEventWriter xmlEventWriterForOutputStream;
    private Transformer transformer;
    private ChildOutputMethod childOutputMethod;

    protected static XMLOutputFactory getXmlOutputFactory() {
        synchronized(TransformIdentity.class) {
            if (xmlOutputFactory == null) {
                xmlOutputFactory = XMLOutputFactory.newInstance();
            }
        }
        return xmlOutputFactory;
    }

    public static XMLInputFactory getXmlInputFactory() {
        synchronized(TransformIdentity.class) {
            if (xmlInputFactory == null) {
                xmlInputFactory = XMLInputFactory.newInstance();
                xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
                xmlInputFactory.setProperty("javax.xml.stream.isSupportingExternalEntities", false);
            }
        }
        return xmlInputFactory;
    }

    @Override
    public void setOutputStream(OutputStream outputStream) throws XMLSecurityException {
        this.outputStream = outputStream;
    }

    protected OutputStream getOutputStream() {
        return this.outputStream;
    }

    protected XMLEventWriter getXmlEventWriterForOutputStream() throws XMLStreamException {
        if (this.xmlEventWriterForOutputStream != null) {
            return this.xmlEventWriterForOutputStream;
        }
        if (this.outputStream != null) {
            return this.xmlEventWriterForOutputStream = getXmlOutputFactory().createXMLEventWriter(new FilterOutputStream(outputStream) {
                @Override
                public void close() throws IOException {
                    //do not close the parent output stream!
                    super.flush();
                }
            });
        }
        return null;
    }

    @Override
    public void setTransformer(Transformer transformer) throws XMLSecurityException {
        this.transformer = transformer;
    }

    protected Transformer getTransformer() {
        return transformer;
    }

    @Override
    public void setProperties(Map<String, Object> properties) throws XMLSecurityException {
        throw new UnsupportedOperationException("no properties supported");
    }

    @Override
    public XMLSecurityConstants.TransformMethod getPreferredTransformMethod(XMLSecurityConstants.TransformMethod forInput) {
        switch (forInput) {
            case XMLSecEvent:
                return XMLSecurityConstants.TransformMethod.XMLSecEvent;
            case InputStream:
                return XMLSecurityConstants.TransformMethod.InputStream;
            default:
                throw new IllegalArgumentException("Unsupported class " + forInput.name());
        }
    }

    @Override
    public void transform(XMLSecEvent xmlSecEvent) throws XMLStreamException {
        if (getXmlEventWriterForOutputStream() != null) {
            //we have an output stream
            getXmlEventWriterForOutputStream().add(xmlSecEvent);
        } else {
            //we have a child transformer
            if (childOutputMethod == null) {

                final XMLSecurityConstants.TransformMethod preferredChildTransformMethod =
                        getTransformer().getPreferredTransformMethod(XMLSecurityConstants.TransformMethod.XMLSecEvent);

                if (preferredChildTransformMethod == XMLSecurityConstants.TransformMethod.XMLSecEvent) {
                    childOutputMethod = new ChildOutputMethod() {

                        @Override
                        public void transform(Object object) throws XMLStreamException {
                            getTransformer().transform((XMLSecEvent) object);
                        }

                        @Override
                        public void doFinal() throws XMLStreamException {
                            getTransformer().doFinal();
                        }
                    };
                } else if (preferredChildTransformMethod == XMLSecurityConstants.TransformMethod.InputStream) {
                    childOutputMethod = new ChildOutputMethod() {

                        private UnsyncByteArrayOutputStream baos;
                        private XMLEventWriter xmlEventWriter;

                        @Override
                        public void transform(Object object) throws XMLStreamException {
                            if (xmlEventWriter == null) {
                                baos = new UnsyncByteArrayOutputStream();
                                xmlEventWriter = getXmlOutputFactory().createXMLEventWriter(baos);
                            }

                            xmlEventWriter.add((XMLSecEvent) object);
                        }

                        @Override
                        public void doFinal() throws XMLStreamException {
                            xmlEventWriter.close();
                            try (InputStream is = new UnsyncByteArrayInputStream(baos.toByteArray())) {
                                getTransformer().transform(is);
                                getTransformer().doFinal();
                            } catch (IOException ex) {
                                throw new XMLStreamException(ex);
                            }
                        }
                    };
                }
            }
            if (childOutputMethod != null) {
                childOutputMethod.transform(xmlSecEvent);
            }
        }
    }

    @Override
    public void transform(final InputStream inputStream) throws XMLStreamException {
        if (getOutputStream() != null) {
            //we have an output stream
            try {
                XMLSecurityUtils.copy(inputStream, getOutputStream());
            } catch (IOException e) {
                throw new XMLStreamException(e);
            }
        } else {
            //we have a child transformer
            if (childOutputMethod == null) {

                final XMLSecurityConstants.TransformMethod preferredChildTransformMethod =
                        getTransformer().getPreferredTransformMethod(XMLSecurityConstants.TransformMethod.InputStream);

                if (preferredChildTransformMethod == XMLSecurityConstants.TransformMethod.XMLSecEvent) {
                    childOutputMethod = new ChildOutputMethod() {

                        private XMLEventReaderInputProcessor xmlEventReaderInputProcessor;

                        @Override
                        public void transform(Object object) throws XMLStreamException {
                            if (xmlEventReaderInputProcessor == null) {
                                xmlEventReaderInputProcessor = new XMLEventReaderInputProcessor(
                                    null,
                                    getXmlInputFactory().createXMLStreamReader(inputStream)
                                );
                            }
                            try {
                                XMLSecEvent xmlSecEvent;
                                do {
                                    xmlSecEvent = xmlEventReaderInputProcessor.processEvent(null);
                                    getTransformer().transform(xmlSecEvent);
                                } while (xmlSecEvent.getEventType() != XMLStreamConstants.END_DOCUMENT);
                            } catch (XMLSecurityException e) {
                                throw new XMLStreamException(e);
                            }
                        }

                        @Override
                        public void doFinal() throws XMLStreamException {
                            getTransformer().doFinal();
                        }
                    };
                } else if (preferredChildTransformMethod == XMLSecurityConstants.TransformMethod.InputStream) {
                    childOutputMethod = new ChildOutputMethod() {

                        @Override
                        public void transform(Object object) throws XMLStreamException {
                            getTransformer().transform(inputStream);
                        }

                        @Override
                        public void doFinal() throws XMLStreamException {
                            getTransformer().doFinal();
                        }

                    };
                }
            }
            if (childOutputMethod != null) {
                childOutputMethod.transform(inputStream);
            }
        }
    }

    @Override
    public void doFinal() throws XMLStreamException {
        if (xmlEventWriterForOutputStream != null) {
            xmlEventWriterForOutputStream.close();
        }
        if (childOutputMethod != null) {
            childOutputMethod.doFinal();
        } else if (transformer != null) {
            transformer.doFinal();
        }
    }

    interface ChildOutputMethod {

        void transform(Object object) throws XMLStreamException;

        void doFinal() throws XMLStreamException;
    }
}
