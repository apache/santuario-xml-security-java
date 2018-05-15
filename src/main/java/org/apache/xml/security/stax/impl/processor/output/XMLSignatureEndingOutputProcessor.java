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
package org.apache.xml.security.stax.impl.processor.output;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityUtils;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.SignaturePartDef;
import org.apache.xml.security.stax.impl.algorithms.SignatureAlgorithm;
import org.apache.xml.security.stax.securityToken.OutboundSecurityToken;
import org.apache.xml.security.stax.securityEvent.SignatureValueSecurityEvent;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants;

import static org.apache.xml.security.stax.ext.XMLSecurityConstants.NS_XMLDSIG_ENVELOPED_SIGNATURE;

/**
 * An EndingOutputProcessor for XML Signature.
 */
public class XMLSignatureEndingOutputProcessor extends AbstractSignatureEndingOutputProcessor {

    private SignedInfoProcessor signedInfoProcessor;

    public XMLSignatureEndingOutputProcessor(XMLSignatureOutputProcessor signatureOutputProcessor) throws XMLSecurityException {
        super(signatureOutputProcessor);
        this.addAfterProcessor(XMLSignatureOutputProcessor.class.getName());
    }

    @Override
    protected SignedInfoProcessor newSignedInfoProcessor(
            SignatureAlgorithm signatureAlgorithm, XMLSecStartElement xmlSecStartElement,
            OutputProcessorChain outputProcessorChain) throws XMLSecurityException {

        this.signedInfoProcessor = new SignedInfoProcessor(signatureAlgorithm, xmlSecStartElement);
        this.signedInfoProcessor.setXMLSecurityProperties(getSecurityProperties());
        this.signedInfoProcessor.setAction(getAction());
        this.signedInfoProcessor.addAfterProcessor(XMLSignatureEndingOutputProcessor.class.getName());
        this.signedInfoProcessor.init(outputProcessorChain);
        return this.signedInfoProcessor;
    }

    @Override
    public void processHeaderEvent(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        super.processHeaderEvent(outputProcessorChain);
        SignatureValueSecurityEvent signatureValueSecurityEvent = new SignatureValueSecurityEvent();
        signatureValueSecurityEvent.setSignatureValue(this.signedInfoProcessor.getSignatureValue());
        outputProcessorChain.getSecurityContext().registerSecurityEvent(signatureValueSecurityEvent);
    }

    @Override
    protected void flushBufferAndCallbackAfterHeader(
            OutputProcessorChain outputProcessorChain, Deque<XMLSecEvent> xmlSecEventDeque)
            throws XMLStreamException, XMLSecurityException {

        // forward to the root element and output it
        XMLSecEvent xmlSecEvent = xmlSecEventDeque.pop();
        while (!xmlSecEvent.isStartElement()) {
            outputProcessorChain.reset();
            outputProcessorChain.processEvent(xmlSecEvent);
            xmlSecEvent = xmlSecEventDeque.pop();
        }
        outputProcessorChain.reset();
        outputProcessorChain.processEvent(xmlSecEvent);

        // search the specified position
        int depth = 0;
        QName signaturePositionQName = getSecurityProperties().getSignaturePositionQName();
        boolean start = getSecurityProperties().isSignaturePositionStart();
        if (signaturePositionQName != null) {
            while (!xmlSecEventDeque.isEmpty()
                && !(start && xmlSecEvent.isStartElement() && xmlSecEvent.asStartElement().getName().equals(signaturePositionQName)
                    || !start && xmlSecEvent.isEndElement() && xmlSecEvent.asEndElement().getName().equals(signaturePositionQName))) {
                xmlSecEvent = xmlSecEventDeque.pop();

                if (xmlSecEvent.isStartElement()) {
                    depth++;
                } else if (xmlSecEvent.isEndElement()) {
                    depth--;
                    if (depth < 0) {
                        // root-end-element reached
                        xmlSecEventDeque.push(xmlSecEvent);
                        break;
                    }
                }

                outputProcessorChain.reset();
                outputProcessorChain.processEvent(xmlSecEvent);
            }
        } else {
            // @see SANTUARIO-405
            // Enhances SANTUARIO-324
            // Output the signature at a specific position.
            // By default, this is just after the root element
            int signaturePosition = getSecurityProperties().getSignaturePosition();
            if (signaturePosition < 0) {
                signaturePosition = 0;
            }
            int position = 0;
            while (position != signaturePosition) {
                xmlSecEvent = xmlSecEventDeque.pop();

                if (xmlSecEvent.isStartElement()) {
                    depth++;
                } else if (xmlSecEvent.isEndElement()) {
                    depth--;
                    if (depth == 0) {
                        position++;
                    } else if (depth < 0) {
                        // root-end-element reached
                        xmlSecEventDeque.push(xmlSecEvent);
                        break;
                    }
                }

                outputProcessorChain.reset();
                outputProcessorChain.processEvent(xmlSecEvent);
            }
        }

        //...then call super to append the signature and flush the rest
        super.flushBufferAndCallbackAfterHeader(outputProcessorChain, xmlSecEventDeque);
    }

    @Override
    protected void createKeyInfoStructureForSignature(
            OutputProcessorChain outputProcessorChain,
            OutboundSecurityToken securityToken,
            boolean useSingleCertificate)
            throws XMLStreamException, XMLSecurityException {
        X509Certificate[] x509Certificates = securityToken.getX509Certificates();
        if (x509Certificates != null) {
            if (getSecurityProperties().getSignatureKeyIdentifiers().isEmpty()) {
                XMLSecurityUtils.createX509IssuerSerialStructure(this, outputProcessorChain, x509Certificates);
            } else {
                List<SecurityTokenConstants.KeyIdentifier> keyIdentifiers = getSecurityProperties().getSignatureKeyIdentifiers();
                // KeyName
                if (keyIdentifiers.remove(SecurityTokenConstants.KeyIdentifier_KeyName)) {
                    String keyName = getSecurityProperties().getSignatureKeyName();
                    XMLSecurityUtils.createKeyNameTokenStructure(this, outputProcessorChain, keyName);
                }

                // KeyValue
                if (keyIdentifiers.remove(SecurityTokenConstants.KeyIdentifier_KeyValue)) {
                    XMLSecurityUtils.createKeyValueTokenStructure(this, outputProcessorChain, x509Certificates);
                }

                // X509Data
                if (!keyIdentifiers.isEmpty()) {
                    createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_X509Data, true, null);

                    for (SecurityTokenConstants.KeyIdentifier keyIdentifier : keyIdentifiers) {
                        if (SecurityTokenConstants.KeyIdentifier_IssuerSerial.equals(keyIdentifier)) {
                            XMLSecurityUtils.createX509IssuerSerialStructure(this, outputProcessorChain, x509Certificates, false);
                        } else if (SecurityTokenConstants.KeyIdentifier_SkiKeyIdentifier.equals(keyIdentifier)) {
                            XMLSecurityUtils.createX509SubjectKeyIdentifierStructure(this, outputProcessorChain, x509Certificates, false);
                        } else if (SecurityTokenConstants.KeyIdentifier_X509KeyIdentifier.equals(keyIdentifier)) {
                            XMLSecurityUtils.createX509CertificateStructure(this, outputProcessorChain, x509Certificates, false);
                        } else if (SecurityTokenConstants.KeyIdentifier_X509SubjectName.equals(keyIdentifier)) {
                            XMLSecurityUtils.createX509SubjectNameStructure(this, outputProcessorChain, x509Certificates, false);
                        } else if (!(SecurityTokenConstants.KeyIdentifier_KeyName.equals(keyIdentifier)
                            || SecurityTokenConstants.KeyIdentifier_KeyValue.equals(keyIdentifier))) {
                            throw new XMLSecurityException("stax.unsupportedToken",
                                                           new Object[] {keyIdentifier});
                        }
                    }

                    createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_X509Data);
                }
            }
        } else if (securityToken.getPublicKey() != null) {
            XMLSecurityUtils.createKeyValueTokenStructure(this, outputProcessorChain, securityToken.getPublicKey());
        }
    }

    @Override
    protected void createTransformsStructureForSignature(OutputProcessorChain subOutputProcessorChain, SignaturePartDef signaturePartDef) throws XMLStreamException, XMLSecurityException {
        if (signaturePartDef.getTransforms() != null) {
            createStartElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_dsig_Transforms, false, null);

            String[] transforms = signaturePartDef.getTransforms();
            for (int i = 0; i < transforms.length; i++) {
                String transform = transforms[i];

                if (!shouldIncludeTransform(transform)) {
                    continue;
                }

                List<XMLSecAttribute> attributes = new ArrayList<>(1);
                attributes.add(createAttribute(XMLSecurityConstants.ATT_NULL_Algorithm, transform));
                createStartElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_dsig_Transform, false, attributes);

                if (getSecurityProperties().isAddExcC14NInclusivePrefixes()) {
                    attributes = new ArrayList<>(1);
                    attributes.add(createAttribute(XMLSecurityConstants.ATT_NULL_PrefixList, signaturePartDef.getInclusiveNamespacesPrefixes()));
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_c14nExcl_InclusiveNamespaces, true, attributes);
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_c14nExcl_InclusiveNamespaces);
                }

                createEndElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_dsig_Transform);
            }
            createEndElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_dsig_Transforms);
        }
    }

    private boolean shouldIncludeTransform(String transform) {
        boolean include = true;

        if (!securityProperties.isSignatureIncludeDigestTransform() &&
                !transform.equals(NS_XMLDSIG_ENVELOPED_SIGNATURE)) {
            include = false;
        }
        return include;
    }
}
