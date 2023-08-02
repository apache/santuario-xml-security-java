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
/*
 * Copyright 2005 Sun Microsystems, Inc. All rights reserved.
 */
package org.apache.jcp.xml.dsig.internal.dom;

import java.io.OutputStream;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Set;

import javax.xml.crypto.Data;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.NodeSetData;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMCryptoContext;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.crypto.dsig.TransformService;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.signature.XMLSignatureNodeInput;
import org.apache.xml.security.signature.XMLSignatureNodeSetInput;
import org.apache.xml.security.signature.XMLSignatureStreamInput;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * This is a wrapper/glue class which invokes the Apache XML-Security
 * Transform.
 *
 */
public abstract class ApacheTransform extends TransformService {

    static {
        org.apache.xml.security.Init.init();
    }

    private static final Logger LOG = System.getLogger(ApacheTransform.class.getName());

    private Transform transform;
    protected Document ownerDoc;
    protected Element transformElem;
    protected TransformParameterSpec params;

    @Override
    public final AlgorithmParameterSpec getParameterSpec() {
        return params;
    }

    @Override
    public void init(XMLStructure parent, XMLCryptoContext context)
        throws InvalidAlgorithmParameterException
    {
        if (context != null && !(context instanceof DOMCryptoContext)) {
            throw new ClassCastException
                ("context must be of type DOMCryptoContext");
        }
        if (parent == null) {
            throw new NullPointerException();
        }
        if (!(parent instanceof javax.xml.crypto.dom.DOMStructure)) {
            throw new ClassCastException("parent must be of type DOMStructure");
        }
        transformElem = (Element)
            ((javax.xml.crypto.dom.DOMStructure) parent).getNode();
        ownerDoc = DOMUtils.getOwnerDocument(transformElem);
    }

    @Override
    public void marshalParams(XMLStructure parent, XMLCryptoContext context)
        throws MarshalException
    {
        if (context != null && !(context instanceof DOMCryptoContext)) {
            throw new ClassCastException
                ("context must be of type DOMCryptoContext");
        }
        if (parent == null) {
            throw new NullPointerException();
        }
        if (!(parent instanceof javax.xml.crypto.dom.DOMStructure)) {
            throw new ClassCastException("parent must be of type DOMStructure");
        }
        transformElem = (Element)
            ((javax.xml.crypto.dom.DOMStructure) parent).getNode();
        ownerDoc = DOMUtils.getOwnerDocument(transformElem);
    }

    @Override
    public Data transform(Data data, XMLCryptoContext xc)
        throws TransformException
    {
        if (data == null) {
            throw new NullPointerException("data must not be null");
        }
        return transformIt(data, xc, null);
    }

    @Override
    public Data transform(Data data, XMLCryptoContext xc, OutputStream os)
        throws TransformException
    {
        if (data == null) {
            throw new NullPointerException("data must not be null");
        }
        if (os == null) {
            throw new NullPointerException("output stream must not be null");
        }
        return transformIt(data, xc, os);
    }

    private Data transformIt(Data data, XMLCryptoContext xc, OutputStream os)
        throws TransformException
    {
        if (ownerDoc == null) {
            throw new TransformException("transform must be marshalled");
        }

        if (transform == null) {
            try {
                transform =
                    new Transform(ownerDoc, getAlgorithm(), transformElem.getChildNodes());
                transform.setElement(transformElem, xc.getBaseURI());
                LOG.log(Level.DEBUG, "Created transform for algorithm: {0}", getAlgorithm());
            } catch (Exception ex) {
                throw new TransformException("Couldn't find Transform for: " +
                                             getAlgorithm(), ex);
            }
        }

        if (Utils.secureValidation(xc)) {
            String algorithm = getAlgorithm();
            if (Transforms.TRANSFORM_XSLT.equals(algorithm)) {
                throw new TransformException(
                    "Transform " + algorithm + " is forbidden when secure validation is enabled"
                );
            }
        }

        XMLSignatureInput in;
        if (data instanceof ApacheData) {
            LOG.log(Level.DEBUG, "ApacheData = true");
            in = ((ApacheData)data).getXMLSignatureInput();
        } else if (data instanceof NodeSetData) {
            LOG.log(Level.DEBUG, "isNodeSet() = true");
            if (data instanceof DOMSubTreeData) {
                LOG.log(Level.DEBUG, "DOMSubTreeData = true");
                DOMSubTreeData subTree = (DOMSubTreeData)data;
                in = new XMLSignatureNodeInput(subTree.getRoot());
                in.setExcludeComments(subTree.excludeComments());
            } else {
                @SuppressWarnings({"unchecked", "rawtypes"})
                Set<Node> nodeSet =
                    Utils.toNodeSet(((NodeSetData)data).iterator());
                in = new XMLSignatureNodeSetInput(nodeSet);
            }
        } else {
            LOG.log(Level.DEBUG, "isNodeSet() = false");
            try {
                in = new XMLSignatureStreamInput(((OctetStreamData) data).getOctetStream());
            } catch (Exception ex) {
                throw new TransformException(ex);
            }
        }
        boolean secVal = Utils.secureValidation(xc);
        in.setSecureValidation(secVal);

        try {
            if (os != null) {
                in = transform.performTransform(in, os, secVal);
                if (!in.isNodeSet() && !in.isElement()) {
                    return null;
                }
            } else {
                in = transform.performTransform(in, secVal);
            }
            if (in.hasUnprocessedInput()) {
                return new ApacheOctetStreamData(in);
            } else {
                return new ApacheNodeSetData(in);
            }
        } catch (Exception ex) {
            throw new TransformException(ex);
        }
    }

    @Override
    public final boolean isFeatureSupported(String feature) {
        if (feature == null) {
            throw new NullPointerException();
        } else {
            return false;
        }
    }
}
