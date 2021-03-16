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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.JCEAlgorithmMapper;
import org.apache.xml.security.stax.config.ResourceResolverMapper;
import org.apache.xml.security.stax.ext.AbstractOutputProcessor;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.ResourceResolver;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.Transformer;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityUtils;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.SignaturePartDef;
import org.apache.xml.security.stax.impl.transformer.TransformIdentity;
import org.apache.xml.security.stax.impl.transformer.canonicalizer.Canonicalizer20010315_Excl;
import org.apache.xml.security.stax.impl.util.DigestOutputStream;
import org.apache.xml.security.utils.UnsyncBufferedOutputStream;
import org.apache.xml.security.utils.XMLUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 */
public abstract class AbstractSignatureOutputProcessor extends AbstractOutputProcessor {

    private static final transient Logger LOG = LoggerFactory.getLogger(AbstractSignatureOutputProcessor.class);

    private final List<SignaturePartDef> signaturePartDefList = new ArrayList<>();
    private InternalSignatureOutputProcessor activeInternalSignatureOutputProcessor;

    public AbstractSignatureOutputProcessor() throws XMLSecurityException {
        super();
    }

    public List<SignaturePartDef> getSignaturePartDefList() {
        return signaturePartDefList;
    }

    @Override
    public abstract void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain)
            throws XMLStreamException, XMLSecurityException;

    @Override
    public void doFinal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        doFinalInternal(outputProcessorChain);
        super.doFinal(outputProcessorChain);
    }

    protected void doFinalInternal(OutputProcessorChain outputProcessorChain) throws XMLSecurityException, XMLStreamException {
        Map<Object, SecurePart> dynamicSecureParts =
                outputProcessorChain.getSecurityContext().getAsMap(XMLSecurityConstants.SIGNATURE_PARTS);
        if (dynamicSecureParts != null) {
            for (Map.Entry<Object, SecurePart> securePartEntry : dynamicSecureParts.entrySet()) {
                final SecurePart securePart = securePartEntry.getValue();
                if (securePart.getExternalReference() != null) {
                    digestExternalReference(outputProcessorChain, securePart);
                }
            }
        }

        verifySignatureParts(outputProcessorChain);
    }

    protected void digestExternalReference(
            OutputProcessorChain outputProcessorChain, SecurePart securePart)
            throws XMLSecurityException, XMLStreamException {

        final String externalReference = securePart.getExternalReference();
        ResourceResolver resourceResolver =
                ResourceResolverMapper.getResourceResolver(
                        externalReference, outputProcessorChain.getDocumentContext().getBaseURI());

        String digestAlgo = securePart.getDigestMethod();
        if (digestAlgo == null) {
            digestAlgo = getSecurityProperties().getSignatureDigestAlgorithm();
        }

        DigestOutputStream digestOutputStream = createMessageDigestOutputStream(digestAlgo);    //NOPMD
        InputStream inputStream = resourceResolver.getInputStreamFromExternalReference();   //NOPMD

        SignaturePartDef signaturePartDef = new SignaturePartDef();
        signaturePartDef.setSecurePart(securePart);
        signaturePartDef.setSigRefId(externalReference);
        signaturePartDef.setExternalResource(true);
        signaturePartDef.setTransforms(securePart.getTransforms());
        signaturePartDef.setDigestAlgo(digestAlgo);

        try {
            if (securePart.getTransforms() != null) {
                signaturePartDef.setExcludeVisibleC14Nprefixes(true);
                Transformer transformer = buildTransformerChain(digestOutputStream, signaturePartDef, null);
                transformer.transform(inputStream);
                transformer.doFinal();
            } else {
                XMLSecurityUtils.copy(inputStream, digestOutputStream);
            }
            digestOutputStream.close();
        } catch (IOException e) {
            throw new XMLSecurityException(e);
        }

        String calculatedDigest =
            XMLUtils.encodeToString(digestOutputStream.getDigestValue());
        LOG.debug("Calculated Digest: {}", calculatedDigest);

        signaturePartDef.setDigestValue(calculatedDigest);

        getSignaturePartDefList().add(signaturePartDef);
    }

    protected void verifySignatureParts(OutputProcessorChain outputProcessorChain) throws XMLSecurityException {
        List<SignaturePartDef> signaturePartDefs = getSignaturePartDefList();
        Map<Object, SecurePart> dynamicSecureParts = outputProcessorChain.getSecurityContext().getAsMap(XMLSecurityConstants.SIGNATURE_PARTS);
        if (dynamicSecureParts != null) {
            Iterator<Map.Entry<Object, SecurePart>> securePartsMapIterator = dynamicSecureParts.entrySet().iterator();
            loop:
            while (securePartsMapIterator.hasNext()) {
                Map.Entry<Object, SecurePart> securePartEntry = securePartsMapIterator.next();
                final SecurePart securePart = securePartEntry.getValue();

                if (securePart.isRequired()) {
                    for (int i = 0; i < signaturePartDefs.size(); i++) {
                        SignaturePartDef signaturePartDef = signaturePartDefs.get(i);

                        if (signaturePartDef.getSecurePart() == securePart) {
                            continue loop;
                        }
                    }
                    throw new XMLSecurityException("stax.signature.securePartNotFound",
                                                   new Object[] {securePart.getName()});
                }
            }
        }
    }

    protected InternalSignatureOutputProcessor getActiveInternalSignatureOutputProcessor() {
        return activeInternalSignatureOutputProcessor;
    }

    protected void setActiveInternalSignatureOutputProcessor(
            InternalSignatureOutputProcessor activeInternalSignatureOutputProcessor) {
        this.activeInternalSignatureOutputProcessor = activeInternalSignatureOutputProcessor;
    }

    protected DigestOutputStream createMessageDigestOutputStream(String digestAlgorithm)
            throws XMLSecurityException {

        String jceName = JCEAlgorithmMapper.translateURItoJCEID(digestAlgorithm);
        String jceProvider = JCEAlgorithmMapper.getJCEProviderFromURI(digestAlgorithm);
        if (jceName == null) {
            throw new XMLSecurityException("algorithms.NoSuchMap",
                                           new Object[] {digestAlgorithm});
        }
        MessageDigest messageDigest;
        try {
            if (jceProvider != null) {
                messageDigest = MessageDigest.getInstance(jceName, jceProvider);
            } else {
                messageDigest = MessageDigest.getInstance(jceName);
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new XMLSecurityException(e);
        }
        return new DigestOutputStream(messageDigest);
    }

    protected Transformer buildTransformerChain(OutputStream outputStream,
                                                SignaturePartDef signaturePartDef,
                                                XMLSecStartElement xmlSecStartElement)
            throws XMLSecurityException {

        String[] transforms = signaturePartDef.getTransforms();

        if (transforms == null || transforms.length == 0) {
            Transformer transformer = new TransformIdentity();
            transformer.setOutputStream(outputStream);
            return transformer;
        }

        Transformer parentTransformer = null;
        for (int i = transforms.length - 1; i >= 0; i--) {
            String transform = transforms[i];

            Map<String, Object> transformerProperties = null;
            if (getSecurityProperties().isAddExcC14NInclusivePrefixes() &&
                    XMLSecurityConstants.NS_C14N_EXCL_OMIT_COMMENTS.equals(transform)) {

                Set<String> prefixSet = XMLSecurityUtils.getExcC14NInclusiveNamespacePrefixes(
                        xmlSecStartElement, signaturePartDef.isExcludeVisibleC14Nprefixes()
                );
                StringBuilder prefixes = new StringBuilder();
                for (Iterator<String> iterator = prefixSet.iterator(); iterator.hasNext(); ) {
                    String prefix = iterator.next();
                    if (prefixes.length() != 0) {
                        prefixes.append(' ');
                    }
                    prefixes.append(prefix);
                }
                signaturePartDef.setInclusiveNamespacesPrefixes(prefixes.toString());
                List<String> inclusiveNamespacePrefixes = new ArrayList<>(prefixSet);
                transformerProperties = new HashMap<>();
                transformerProperties.put(
                        Canonicalizer20010315_Excl.INCLUSIVE_NAMESPACES_PREFIX_LIST, inclusiveNamespacePrefixes);
            }

            if (parentTransformer != null) {
                parentTransformer = XMLSecurityUtils.getTransformer(
                        parentTransformer, null, transformerProperties, transform, XMLSecurityConstants.DIRECTION.OUT);
            } else {
                parentTransformer = XMLSecurityUtils.getTransformer(
                        null, outputStream, transformerProperties, transform, XMLSecurityConstants.DIRECTION.OUT);
            }
        }
        return parentTransformer;
    }

    public class InternalSignatureOutputProcessor extends AbstractOutputProcessor {

        private SignaturePartDef signaturePartDef;
        private XMLSecStartElement xmlSecStartElement;
        private int elementCounter;

        private OutputStream bufferedDigestOutputStream;
        private DigestOutputStream digestOutputStream;
        private Transformer transformer;

        public InternalSignatureOutputProcessor(SignaturePartDef signaturePartDef, XMLSecStartElement xmlSecStartElement)
                throws XMLSecurityException {
            super();
            this.addBeforeProcessor(InternalSignatureOutputProcessor.class);
            this.signaturePartDef = signaturePartDef;
            this.xmlSecStartElement = xmlSecStartElement;
        }

        @Override
        public void init(OutputProcessorChain outputProcessorChain) throws XMLSecurityException {
            this.digestOutputStream = createMessageDigestOutputStream(signaturePartDef.getDigestAlgo());
            this.bufferedDigestOutputStream = new UnsyncBufferedOutputStream(digestOutputStream);
            this.transformer = buildTransformerChain(this.bufferedDigestOutputStream, signaturePartDef, xmlSecStartElement);
            super.init(outputProcessorChain);
        }

        @Override
        public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain)
                throws XMLStreamException, XMLSecurityException {

            transformer.transform(xmlSecEvent);

            if (XMLStreamConstants.START_ELEMENT == xmlSecEvent.getEventType()) {
                elementCounter++;
            } else if (XMLStreamConstants.END_ELEMENT == xmlSecEvent.getEventType()) {
                elementCounter--;

                if (elementCounter == 0 &&
                    xmlSecEvent.asEndElement().getName().equals(this.xmlSecStartElement.getName())) {

                    transformer.doFinal();
                    try {
                        bufferedDigestOutputStream.close();
                    } catch (IOException e) {
                        throw new XMLSecurityException(e);
                    }
                    String calculatedDigest =
                        XMLUtils.encodeToString(this.digestOutputStream.getDigestValue());
                    LOG.debug("Calculated Digest: {}", calculatedDigest);
                    signaturePartDef.setDigestValue(calculatedDigest);

                    outputProcessorChain.removeProcessor(this);
                    //from now on signature is possible again
                    setActiveInternalSignatureOutputProcessor(null);
                }
            }
            outputProcessorChain.processEvent(xmlSecEvent);
        }
    }
}
