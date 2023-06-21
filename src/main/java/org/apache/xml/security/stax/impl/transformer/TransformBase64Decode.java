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

import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;

import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.codec.binary.Base64OutputStream;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.processor.input.XMLEventReaderInputProcessor;
import org.apache.xml.security.utils.UnsyncByteArrayInputStream;
import org.apache.xml.security.utils.UnsyncByteArrayOutputStream;

/**
 */
public class TransformBase64Decode extends TransformIdentity {

    private ChildOutputMethod childOutputMethod;

    @Override
    public void setOutputStream(OutputStream outputStream) throws XMLSecurityException {
        super.setOutputStream(new Base64OutputStream(
                new FilterOutputStream(outputStream) {
                    @Override
                    public void close() throws IOException {
                        //do not close the parent output stream!
                        super.flush();
                    }
                },
                false)
        );
    }

    @Override
    public XMLSecurityConstants.TransformMethod getPreferredTransformMethod(XMLSecurityConstants.TransformMethod forInput) {
        switch (forInput) {
            case XMLSecEvent:
                return XMLSecurityConstants.TransformMethod.InputStream;
            case InputStream:
                return XMLSecurityConstants.TransformMethod.InputStream;
            default:
                throw new IllegalArgumentException("Unsupported class " + forInput.name());
        }
    }

    @Override
    public void transform(XMLSecEvent xmlSecEvent) throws XMLStreamException {
        int eventType = xmlSecEvent.getEventType();
        if (XMLStreamConstants.CHARACTERS == eventType) {
            if (getOutputStream() != null) {
                //we have an output stream
                //encoding shouldn't matter here, because the data is Base64 encoded and is therefore in the ASCII range.
                try {
                    getOutputStream().write(xmlSecEvent.asCharacters().getData().getBytes());
                } catch (IOException e) {
                    throw new XMLStreamException(e);
                }
            } else {
                //we have a child transformer
                if (childOutputMethod == null) {

                    final XMLSecurityConstants.TransformMethod preferredChildTransformMethod =
                        getTransformer().getPreferredTransformMethod(XMLSecurityConstants.TransformMethod.XMLSecEvent);

                    if (preferredChildTransformMethod == XMLSecurityConstants.TransformMethod.XMLSecEvent) {
                        childOutputMethod = new ChildOutputMethod() {

                            private UnsyncByteArrayOutputStream byteArrayOutputStream;
                            private Base64OutputStream base64OutputStream;

                            @Override
                            public void transform(Object object) throws XMLStreamException {
                                if (base64OutputStream == null) {
                                    byteArrayOutputStream = new UnsyncByteArrayOutputStream();
                                    base64OutputStream = new Base64OutputStream(byteArrayOutputStream, false);
                                }
                                try {
                                    base64OutputStream.write((byte[]) object);
                                } catch (IOException e) {
                                    throw new XMLStreamException(e);
                                }
                            }

                            @Override
                            public void doFinal() throws XMLStreamException {
                                try {
                                    base64OutputStream.close();
                                } catch (IOException e) {
                                    throw new XMLStreamException(e);
                                }

                                try (InputStream is = new UnsyncByteArrayInputStream(byteArrayOutputStream.toByteArray())) {
                                    XMLEventReaderInputProcessor xmlEventReaderInputProcessor
                                    = new XMLEventReaderInputProcessor(null,
                                                                       getXmlInputFactory().createXMLStreamReader(is)
                                        );
                                    XMLSecEvent xmlSecEvent;
                                    do {
                                        xmlSecEvent = xmlEventReaderInputProcessor.processEvent(null);
                                        getTransformer().transform(xmlSecEvent);
                                    } while (xmlSecEvent.getEventType() != XMLStreamConstants.END_DOCUMENT);
                                } catch (XMLSecurityException | IOException e) {
                                    throw new XMLStreamException(e);
                                }
                                getTransformer().doFinal();
                            }
                        };
                    } else if (preferredChildTransformMethod == XMLSecurityConstants.TransformMethod.InputStream) {
                        childOutputMethod = new ChildOutputMethod() {

                            private UnsyncByteArrayOutputStream byteArrayOutputStream;
                            private Base64OutputStream base64OutputStream;

                            @Override
                            public void transform(Object object) throws XMLStreamException {
                                if (base64OutputStream == null) {
                                    byteArrayOutputStream = new UnsyncByteArrayOutputStream();
                                    base64OutputStream = new Base64OutputStream(byteArrayOutputStream, false);
                                }
                                try {
                                    base64OutputStream.write((byte[]) object);
                                } catch (IOException e) {
                                    throw new XMLStreamException(e);
                                }
                            }

                            @Override
                            public void doFinal() throws XMLStreamException {
                                try {
                                    base64OutputStream.close();
                                } catch (IOException e) {
                                    throw new XMLStreamException(e);
                                }
                                try (InputStream is = new UnsyncByteArrayInputStream(byteArrayOutputStream.toByteArray())) {
                                    getTransformer().transform(is);
                                    getTransformer().doFinal();
                                } catch (IOException ex) {
                                    throw new XMLStreamException(ex);
                                }
                            }
                        };
                    }
                    if (childOutputMethod != null) {
                        childOutputMethod.transform(xmlSecEvent.asCharacters().getData().getBytes());
                    }
                }
            }
        }
    }

    @Override
    public void transform(InputStream inputStream) throws XMLStreamException {
        if (getOutputStream() != null) {
            super.transform(inputStream);
        } else {
            super.transform(new Base64InputStream(inputStream, false));
        }
    }

    @Override
    public void doFinal() throws XMLStreamException {
        if (getOutputStream() != null) {
            try {
                getOutputStream().close();
            } catch (IOException e) {
                throw new XMLStreamException(e);
            }
        }
        if (childOutputMethod != null) {
            childOutputMethod.doFinal();
        } else if (getTransformer() != null) {
            getTransformer().doFinal();
        }
    }
}
