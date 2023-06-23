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
package org.apache.xml.security.test.stax.transformer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.Init;
import org.apache.xml.security.stax.ext.Transformer;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityUtils;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.transformer.TransformBase64Decode;
import org.apache.xml.security.test.stax.utils.XMLSecEventAllocator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

/**
 */
class TransformBase64DecodeTest {

    private XMLInputFactory xmlInputFactory;

    @BeforeEach
    public void setUp() throws Exception {
        Init.init(this.getClass().getClassLoader().getResource("security-config.xml").toURI(),
                this.getClass());
        this.xmlInputFactory = XMLInputFactory.newInstance();
        this.xmlInputFactory.setEventAllocator(new XMLSecEventAllocator());
    }

    @Test
    void testXMLSecEventToXMLSecEventAPI() throws Exception {
        TransformBase64Decode transformBase64Decode = new TransformBase64Decode();

        final List<XMLSecEvent> xmlSecEvents = new ArrayList<>();

        Transformer transformer = new Transformer() {
            @Override
            public void setOutputStream(OutputStream outputStream) throws XMLSecurityException {
            }

            @Override
            public void setTransformer(Transformer transformer) throws XMLSecurityException {
            }

            @Override
            public void setProperties(Map<String, Object> properties) throws XMLSecurityException {
            }

            @Override
            public XMLSecurityConstants.TransformMethod getPreferredTransformMethod(XMLSecurityConstants.TransformMethod forInput) {
                return XMLSecurityConstants.TransformMethod.XMLSecEvent;
            }

            @Override
            public void transform(XMLSecEvent xmlSecEvent) throws XMLStreamException {
                xmlSecEvents.add(xmlSecEvent);
            }

            @Override
            public void transform(InputStream inputStream) throws XMLStreamException {
                fail("unexpected call to transform(InputStream");
            }

            @Override
            public void doFinal() throws XMLStreamException {
            }
        };
        transformBase64Decode.setTransformer(transformer);

        XMLEventReader xmlSecEventReader = xmlInputFactory.createXMLEventReader(
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext-base64.xml")
        );

        XMLSecEvent xmlSecEvent = null;
        while (xmlSecEventReader.hasNext()) {
            xmlSecEvent = (XMLSecEvent) xmlSecEventReader.nextEvent();
            if (xmlSecEvent.isStartElement() && xmlSecEvent.asStartElement().getName().equals(new QName("urn:example:po", "PaymentInfo"))) {
                break;
            }
        }
        while (xmlSecEventReader.hasNext()) {
            transformBase64Decode.transform(xmlSecEvent);
            if (xmlSecEvent.isEndElement() && xmlSecEvent.asEndElement().getName().equals(new QName("urn:example:po", "PaymentInfo"))) {
                break;
            }
            xmlSecEvent = (XMLSecEvent) xmlSecEventReader.nextEvent();
        }

        transformBase64Decode.doFinal();

        assertEquals(16, xmlSecEvents.size());
    }

    @Test
    void testXMLSecEventToInputStreamAPI() throws Exception {
        TransformBase64Decode transformBase64Decode = new TransformBase64Decode();

        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        Transformer transformer = new Transformer() {
            @Override
            public void setOutputStream(OutputStream outputStream) throws XMLSecurityException {
            }

            @Override
            public void setTransformer(Transformer transformer) throws XMLSecurityException {
            }

            @Override
            public void setProperties(Map<String, Object> properties) throws XMLSecurityException {
            }

            @Override
            public XMLSecurityConstants.TransformMethod getPreferredTransformMethod(XMLSecurityConstants.TransformMethod forInput) {
                return XMLSecurityConstants.TransformMethod.InputStream;
            }

            @Override
            public void transform(XMLSecEvent xmlSecEvent) throws XMLStreamException {
                fail("unexpected call to transform(XMLSecEvent");
            }

            @Override
            public void transform(InputStream inputStream) throws XMLStreamException {
                try {
                    XMLSecurityUtils.copy(inputStream, byteArrayOutputStream);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }

            @Override
            public void doFinal() throws XMLStreamException {
            }
        };
        transformBase64Decode.setTransformer(transformer);

        XMLEventReader xmlSecEventReader = xmlInputFactory.createXMLEventReader(
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext-base64.xml")
        );

        XMLSecEvent xmlSecEvent = null;
        while (xmlSecEventReader.hasNext()) {
            xmlSecEvent = (XMLSecEvent) xmlSecEventReader.nextEvent();
            if (xmlSecEvent.isStartElement() && xmlSecEvent.asStartElement().getName().equals(new QName("urn:example:po", "PaymentInfo"))) {
                break;
            }
        }
        while (xmlSecEventReader.hasNext()) {
            transformBase64Decode.transform(xmlSecEvent);
            if (xmlSecEvent.isEndElement() && xmlSecEvent.asEndElement().getName().equals(new QName("urn:example:po", "PaymentInfo"))) {
                break;
            }
            xmlSecEvent = (XMLSecEvent) xmlSecEventReader.nextEvent();
        }

        transformBase64Decode.doFinal();

        assertEquals(153, byteArrayOutputStream.size());
    }

    @Test
    void testXMLSecEventToOutputStreamStreamAPI() throws Exception {
        TransformBase64Decode transformBase64Decode = new TransformBase64Decode();
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        transformBase64Decode.setOutputStream(byteArrayOutputStream);

        XMLEventReader xmlSecEventReader = xmlInputFactory.createXMLEventReader(
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext-base64.xml")
        );

        XMLSecEvent xmlSecEvent = null;
        while (xmlSecEventReader.hasNext()) {
            xmlSecEvent = (XMLSecEvent) xmlSecEventReader.nextEvent();
            if (xmlSecEvent.isStartElement() && xmlSecEvent.asStartElement().getName().equals(new QName("urn:example:po", "PaymentInfo"))) {
                break;
            }
        }
        while (xmlSecEventReader.hasNext()) {
            transformBase64Decode.transform(xmlSecEvent);
            if (xmlSecEvent.isEndElement() && xmlSecEvent.asEndElement().getName().equals(new QName("urn:example:po", "PaymentInfo"))) {
                break;
            }
            xmlSecEvent = (XMLSecEvent) xmlSecEventReader.nextEvent();
        }

        transformBase64Decode.doFinal();

        assertEquals(153, byteArrayOutputStream.size());
    }

    @Test
    void testInputStreamToOutputStreamStreamAPI() throws Exception {
        TransformBase64Decode transformBase64Decode = new TransformBase64Decode();
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        transformBase64Decode.setOutputStream(byteArrayOutputStream);

        transformBase64Decode.transform(this.getClass().getClassLoader().getResourceAsStream(
                "ie/baltimore/merlin-examples/merlin-xmldsig-twenty-three/xml-stylesheet.b64"));

        assertEquals(13132, byteArrayOutputStream.size());
    }

    @Test
    void testInputStreamToXMLSecEventAPI() throws Exception {
        TransformBase64Decode transformBase64Decode = new TransformBase64Decode();
        final List<XMLSecEvent> xmlSecEvents = new ArrayList<>();

        Transformer transformer = new Transformer() {
            @Override
            public void setOutputStream(OutputStream outputStream) throws XMLSecurityException {
            }

            @Override
            public void setTransformer(Transformer transformer) throws XMLSecurityException {
            }

            @Override
            public void setProperties(Map<String, Object> properties) throws XMLSecurityException {
            }

            @Override
            public XMLSecurityConstants.TransformMethod getPreferredTransformMethod(XMLSecurityConstants.TransformMethod forInput) {
                return XMLSecurityConstants.TransformMethod.XMLSecEvent;
            }

            @Override
            public void transform(XMLSecEvent xmlSecEvent) throws XMLStreamException {
                xmlSecEvents.add(xmlSecEvent);
            }

            @Override
            public void transform(InputStream inputStream) throws XMLStreamException {
                fail("unexpected call to transform(InputStream");
            }

            @Override
            public void doFinal() throws XMLStreamException {
            }
        };

        transformBase64Decode.setTransformer(transformer);

        transformBase64Decode.transform(this.getClass().getClassLoader().getResourceAsStream(
                "ie/baltimore/merlin-examples/merlin-xmlenc-five/base64.xml"));

        transformBase64Decode.doFinal();

        assertEquals(44, xmlSecEvents.size());
    }

    @Test
    void testInputStreamToInputStreamAPI() throws Exception {
        TransformBase64Decode transformBase64Decode = new TransformBase64Decode();
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        Transformer transformer = new Transformer() {
            @Override
            public void setOutputStream(OutputStream outputStream) throws XMLSecurityException {
            }

            @Override
            public void setTransformer(Transformer transformer) throws XMLSecurityException {
            }

            @Override
            public void setProperties(Map<String, Object> properties) throws XMLSecurityException {
            }

            @Override
            public XMLSecurityConstants.TransformMethod getPreferredTransformMethod(XMLSecurityConstants.TransformMethod forInput) {
                return XMLSecurityConstants.TransformMethod.InputStream;
            }

            @Override
            public void transform(XMLSecEvent xmlSecEvent) throws XMLStreamException {
                fail("unexpected call to transform(XMLSecEvent");
            }

            @Override
            public void transform(InputStream inputStream) throws XMLStreamException {
                try {
                    XMLSecurityUtils.copy(inputStream, byteArrayOutputStream);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }

            @Override
            public void doFinal() throws XMLStreamException {
            }
        };

        transformBase64Decode.setTransformer(transformer);

        transformBase64Decode.transform(this.getClass().getClassLoader().getResourceAsStream(
                "ie/baltimore/merlin-examples/merlin-xmlenc-five/base64.xml"));

        transformBase64Decode.doFinal();

        assertEquals(615, byteArrayOutputStream.size());
    }
}
