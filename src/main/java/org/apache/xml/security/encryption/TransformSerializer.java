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
package org.apache.xml.security.encryption;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.xml.XMLConstants;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.stream.StreamSource;

import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.w3c.dom.Document;
import org.w3c.dom.DocumentFragment;
import org.w3c.dom.Node;

/**
 * Converts <code>String</code>s into <code>Node</code>s and visa versa. This requires Xalan to
 * work properly.
 */
public class TransformSerializer extends AbstractSerializer {

    private final TransformerFactory transformerFactory;

    public TransformSerializer(boolean secureValidation) throws InvalidCanonicalizerException, TransformerConfigurationException {
        this(Canonicalizer.ALGO_ID_C14N_PHYSICAL, secureValidation);
    }

    public TransformSerializer(String canonAlg, boolean secureValidation) throws TransformerConfigurationException, InvalidCanonicalizerException {
        super(canonAlg, secureValidation);

        transformerFactory = TransformerFactory.newInstance();
        transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, Boolean.TRUE);
        if (secureValidation) {
            try {
                transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
                transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
            } catch (IllegalArgumentException ex) {
                // ignore
            }
        }
    }

    /**
     * @param source
     * @param ctx
     * @return the Node resulting from the parse of the source
     * @throws XMLEncryptionException
     */
    @Override
    public Node deserialize(byte[] source, Node ctx) throws XMLEncryptionException, IOException {
        byte[] fragment = createContext(source, ctx);
        try (InputStream is = new ByteArrayInputStream(fragment)) {
            return deserialize(ctx, new StreamSource(is));
        }
    }

    /**
     * @param ctx
     * @param source
     * @return the Node resulting from the parse of the source
     * @throws XMLEncryptionException
     */
    private Node deserialize(Node ctx, Source source) throws XMLEncryptionException {
        try {
            Document contextDocument = null;
            if (Node.DOCUMENT_NODE == ctx.getNodeType()) {
                contextDocument = (Document)ctx;
            } else {
                contextDocument = ctx.getOwnerDocument();
            }

            Transformer transformer = transformerFactory.newTransformer();

            DOMResult res = new DOMResult();

            Node placeholder = contextDocument.createDocumentFragment();
            res.setNode(placeholder);

            transformer.transform(source, res);

            // Skip dummy element
            Node dummyChild = placeholder.getFirstChild();
            Node child = dummyChild.getFirstChild();

            if (child != null && child.getNextSibling() == null) {
                return child;
            }

            DocumentFragment docfrag = contextDocument.createDocumentFragment();
            while (child != null) {
                dummyChild.removeChild(child);
                docfrag.appendChild(child);
                child = dummyChild.getFirstChild();
            }

            return docfrag;
        } catch (Exception e) {
            throw new XMLEncryptionException(e);
        }
    }

}
