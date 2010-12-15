/*
 * Copyright 2007 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package com.r_bg.stax.transforms;

import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import javax.xml.crypto.Data;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.crypto.dsig.TransformService;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.stream.XMLStreamReader;

import com.r_bg.stax.StaxData;
import com.r_bg.stax.c14n.AttributeHandleExclusive;
import com.r_bg.stax.c14n.C14n;

/**
 * Stax-based implementation of Inclusive C14N TransformService.
 *
 * @author Sean Mullan
 */
public class StaxInclusiveC14N extends TransformService {

    private C14n c14n;

    public void init(TransformParameterSpec params) 
	throws InvalidAlgorithmParameterException { 
	if (params != null) {
	    throw new InvalidAlgorithmParameterException("params must be null");
	}
    }

    public void init(XMLStructure parent, XMLCryptoContext context) 
	throws InvalidAlgorithmParameterException {
	if (parent == null) {
	    throw new NullPointerException();
	}
    }

    public void marshalParams(XMLStructure parent, XMLCryptoContext context) 
	throws MarshalException {
	if (parent == null) {
	    throw new NullPointerException();
	}
    }

    public Data transform(Data data, XMLCryptoContext context) 
	throws TransformException {
	throw new UnsupportedOperationException();
    }

    public Data transform(Data data, XMLCryptoContext context, OutputStream os)
	throws TransformException {
	XMLStreamReader reader = ((StaxData) data).getXMLStreamReader();
	if (c14n == null) {
	    c14n = new C14n(new AttributeHandleExclusive(), os, false);
	}
	c14n.accept(reader);
	return null;
    }

    public AlgorithmParameterSpec getParameterSpec() {
	return null;
    }

    public boolean isFeatureSupported(String feature) {
	return false;
    }
}
