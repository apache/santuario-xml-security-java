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
package org.apache.xml.security.test.javax.xml.crypto.dsig;

import java.io.File;
import java.io.InputStream;
import java.util.Objects;

import javax.xml.crypto.KeySelector;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;

import org.apache.xml.security.parser.XMLParserException;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.traversal.DocumentTraversal;
import org.w3c.dom.traversal.NodeFilter;
import org.w3c.dom.traversal.NodeIterator;

/**
 * This is a class which performs xml signature validation upon request
 */
public class SignatureValidator {

    private final File dir;

    public SignatureValidator() {
        this.dir = null;
    }


    /**
     * @param base can be null. Base directory
     */
    public SignatureValidator(File base) {
        dir = Objects.requireNonNull(base, "basic directory");
    }


    public boolean validate(String fn, KeySelector ks) throws Exception {
        return validate(fn, ks, null);
    }


    public DOMValidateContext getValidateContext(String fn, KeySelector ks) throws Exception {
        return getValidateContext(fn, ks, true);
    }


    public DOMValidateContext getValidateContext(InputStream signedXml, KeySelector ks, boolean secureValidation)
        throws XMLParserException {
        Document doc = XMLUtils.read(signedXml, false);
        return getValidateContext(doc, ks, secureValidation);
    }


    public DOMValidateContext getValidateContext(String fileName, KeySelector ks, boolean secureValidation)
        throws Exception {
        if (dir == null) {
            throw new IllegalArgumentException("Basic directory was not set, files not supported.");
        }
        Document doc = XMLUtils.read(new File(dir, fileName), false);
        return getValidateContext(doc, ks, secureValidation);
    }


    public DOMValidateContext getValidateContext(Document doc, KeySelector ks, boolean secureValidation) {
        Element sigElement = getSignatureElement(doc);
        if (sigElement == null) {
            throw new IllegalArgumentException("Couldn't find signature Element");
        }
        DOMValidateContext vc = new DOMValidateContext(ks, sigElement);
        vc.setProperty("org.apache.jcp.xml.dsig.secureValidation", secureValidation);
        if (dir != null) {
            vc.setBaseURI(dir.toURI().toString());
        }
        return vc;
    }


    public boolean validate(String fileName, KeySelector ks, URIDereferencer ud) throws Exception {
        return validate(fileName, ks, ud, true);
    }


    public boolean validate(String fileName, KeySelector ks, URIDereferencer ud, boolean secureValidation)
        throws Exception {
        DOMValidateContext vc = getValidateContext(fileName, ks, secureValidation);
        if (ud != null) {
            vc.setURIDereferencer(ud);
        }
        return validate(vc);
    }

    public boolean validate(DOMValidateContext vc) throws Exception {
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM",
            new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
        XMLSignature signature = factory.unmarshalXMLSignature(vc);
        boolean coreValidity = signature.validate(vc);

        // Check core validation status
        if (!coreValidity) {
            for (Reference reference : signature.getSignedInfo().getReferences()) {
                reference.validate(vc);
            }
        }
        return coreValidity;
    }

    public static Element getSignatureElement(Document doc) {
        NodeIterator ni = ((DocumentTraversal) doc).createNodeIterator(doc.getDocumentElement(),
            NodeFilter.SHOW_ELEMENT, null, false);

        for (Node n = ni.nextNode(); n != null; n = ni.nextNode() ) {
            if ("Signature".equals(n.getLocalName())) {
                return (Element) n;
            }
        }
        return null;
    }
}
