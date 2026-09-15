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
package org.apache.xml.security.test.stax.signature;

import java.util.Collections;
import java.util.List;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;

import org.apache.xml.security.binding.xmldsig.DigestMethodType;
import org.apache.xml.security.binding.xmldsig.ReferenceType;
import org.apache.xml.security.binding.xmldsig.SignatureType;
import org.apache.xml.security.binding.xmldsig.SignedInfoType;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.Init;
import org.apache.xml.security.stax.ext.AbstractInputProcessor;
import org.apache.xml.security.stax.ext.InputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecEventFactory;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.DocumentContextImpl;
import org.apache.xml.security.stax.impl.InboundSecurityContextImpl;
import org.apache.xml.security.stax.impl.InputProcessorChainImpl;
import org.apache.xml.security.stax.impl.processor.input.AbstractSignatureReferenceVerifyInputProcessor;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the bookkeeping of DocumentContext.isInSignedContent() done by
 * AbstractSignatureReferenceVerifyInputProcessor. 
 */
class SignedContentMarkerTest {

    private static final String REFERENCE_ID = "reference-id";

    @BeforeEach
    public void setUp() throws Exception {
        Init.init(this.getClass().getClassLoader().getResource("security-config.xml").toURI(), this.getClass());
    }

    @Test
    void verifierFinishedDuringConstructionLeavesNoSignedContentMarker() throws Exception {
        DocumentContextImpl documentContext = new DocumentContextImpl();
        InputProcessorChainImpl inputProcessorChain =
                new InputProcessorChainImpl(new InboundSecurityContextImpl(), documentContext);
        inputProcessorChain.addProcessor(new EventSourceInputProcessor(createReferencedStartElement()));

        TestSignatureReferenceVerifyInputProcessor processor =
                new TestSignatureReferenceVerifyInputProcessor(inputProcessorChain, true);
        processor.processEvent(inputProcessorChain);

        assertFalse(documentContext.isInSignedContent(),
                "a verifier that finished during construction must not leave a signed content marker behind");
        assertTrue(documentContext.getContentTypeMap().isEmpty());
    }

    @Test
    void verifierAddedToTheChainRegistersASignedContentMarker() throws Exception {
        DocumentContextImpl documentContext = new DocumentContextImpl();
        InputProcessorChainImpl inputProcessorChain =
                new InputProcessorChainImpl(new InboundSecurityContextImpl(), documentContext);
        inputProcessorChain.addProcessor(new EventSourceInputProcessor(createReferencedStartElement()));

        TestSignatureReferenceVerifyInputProcessor processor =
                new TestSignatureReferenceVerifyInputProcessor(inputProcessorChain, false);
        processor.processEvent(inputProcessorChain);

        assertTrue(documentContext.isInSignedContent(),
                "a verifier that is processing the referenced element is in signed content");
    }

    @Test
    void unsetWithoutAMatchingSetIsANoOp() {
        DocumentContextImpl documentContext = new DocumentContextImpl();

        assertDoesNotThrow(() -> documentContext.unsetIsInSignedContent(new Object()));
        assertDoesNotThrow(() -> documentContext.unsetIsInEncryptedContent(new Object()));
        assertFalse(documentContext.isInSignedContent());
        assertFalse(documentContext.isInEncryptedContent());
    }

    private XMLSecStartElement createReferencedStartElement() {
        return XMLSecEventFactory.createXmlSecStartElement(
                new QName("urn:test", "Signed"),
                Collections.singletonList(XMLSecEventFactory.createXMLSecAttribute(
                        XMLSecurityConstants.ATT_NULL_Id, REFERENCE_ID)),
                null);
    }

    private static SignatureType createSignatureType() {
        DigestMethodType digestMethodType = new DigestMethodType();
        digestMethodType.setAlgorithm(XMLSecurityConstants.NS_XENC_SHA256);

        ReferenceType referenceType = new ReferenceType();
        referenceType.setURI("#" + REFERENCE_ID);
        referenceType.setDigestMethod(digestMethodType);
        referenceType.setDigestValue(new byte[32]);

        SignedInfoType signedInfoType = new SignedInfoType();
        signedInfoType.getReference().add(referenceType);

        SignatureType signatureType = new SignatureType();
        signatureType.setSignedInfo(signedInfoType);
        return signatureType;
    }

    /**
     * Hands out the one event the chain is built around.
     */
    private static final class EventSourceInputProcessor extends AbstractInputProcessor {

        private final XMLSecEvent xmlSecEvent;

        EventSourceInputProcessor(XMLSecEvent xmlSecEvent) {
            super(new XMLSecurityProperties());
            this.xmlSecEvent = xmlSecEvent;
        }

        @Override
        public XMLSecEvent processHeaderEvent(InputProcessorChain inputProcessorChain) {
            return xmlSecEvent;
        }

        @Override
        public XMLSecEvent processEvent(InputProcessorChain inputProcessorChain) {
            return xmlSecEvent;
        }
    }

    /**
     * Stands in for a subclass such as WSS4J's WSSSignatureReferenceVerifyInputProcessor, which
     * finishes the verifier of an STR-Transform reference inside its constructor.
     */
    private static final class TestSignatureReferenceVerifyInputProcessor
            extends AbstractSignatureReferenceVerifyInputProcessor {

        private final boolean finishVerifierDuringConstruction;

        TestSignatureReferenceVerifyInputProcessor(
                InputProcessorChain inputProcessorChain, boolean finishVerifierDuringConstruction)
                throws XMLSecurityException {
            super(inputProcessorChain, createSignatureType(), (InboundSecurityToken) null, new XMLSecurityProperties());
            this.finishVerifierDuringConstruction = finishVerifierDuringConstruction;
        }

        @Override
        protected void processElementPath(
                List<QName> elementPath, InputProcessorChain inputProcessorChain, XMLSecEvent xmlSecEvent,
                ReferenceType referenceType) {
            //not of interest here
        }

        @Override
        protected InternalSignatureReferenceVerifier getSignatureReferenceVerifier(
                XMLSecurityProperties securityProperties, InputProcessorChain inputProcessorChain,
                ReferenceType referenceType, XMLSecStartElement startElement) throws XMLSecurityException {

            InternalSignatureReferenceVerifier verifier = super.getSignatureReferenceVerifier(
                    securityProperties, inputProcessorChain, referenceType, startElement);
            if (finishVerifierDuringConstruction) {
                verifier.setFinished(true);
            }
            return verifier;
        }

        @Override
        public XMLSecEvent processEvent(InputProcessorChain inputProcessorChain)
                throws XMLStreamException, XMLSecurityException {
            inputProcessorChain.reset();
            return super.processEvent(inputProcessorChain);
        }
    }
}
