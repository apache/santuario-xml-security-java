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
package com.r_bg.stax;

import javax.xml.crypto.*;
import javax.xml.crypto.dsig.*;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import org.jcp.xml.dsig.internal.SignerOutputStream;

/**
 * StAX-based implementation of SignatureMethod for RSA algorithm.
 *
 * @author Sean Mullan
 */
public final class StaxRSASignatureMethod extends StaxSignatureMethod { 

    private Signature signature;

    public String getAlgorithm() {
	return SignatureMethod.RSA_SHA1;
    }

    public AlgorithmParameterSpec getParameterSpec() {
	return null;
    }

    public StaxWorker read(XMLStreamReader reader) {
	return null;
    }

    public StaxWatcher remove() {
	return null;
    }

    protected void marshalParams(XMLStreamWriter writer, String dsPrefix)
        throws XMLStreamException { }

    protected boolean paramsEqual(AlgorithmParameterSpec spec) {
	// params should always be null
	return (getParameterSpec() == spec);
    }

    public boolean verify(Key key, byte[] bytes, byte[] sig,
	XMLValidateContext context) 
	throws InvalidKeyException, SignatureException, XMLSignatureException {
    	if (key == null || bytes == null || sig == null) {
    	    throw new NullPointerException
		("key, bytes or signature cannot be null");
    	}

        if (!(key instanceof PublicKey)) {
	    throw new InvalidKeyException("key must be PublicKey");
        }
	if (signature == null) {
	    try {
                // FIXME: do other hashes besides sha-1
                signature = Signature.getInstance("SHA1withRSA");
	    } catch (NoSuchAlgorithmException nsae) {
		throw new SignatureException("SHA1withRSA Signature not found");
	    }
	}
        signature.initVerify((PublicKey) key);
	signature.update(bytes);

	return signature.verify(sig);
    }

    public byte[] sign(Key key, byte[] bytes, XMLSignContext context) 
	throws InvalidKeyException, XMLSignatureException {
    	if (key == null || bytes == null) {
    	    throw new NullPointerException();
    	}

        if (!(key instanceof PrivateKey)) {
            throw new InvalidKeyException("key must be PrivateKey");
        }
	if (signature == null) {
	    try {
                // FIXME: do other hashes besides sha-1
                signature = Signature.getInstance("SHA1withRSA");
	    } catch (NoSuchAlgorithmException nsae) {
		throw new InvalidKeyException("SHA1withRSA Signature not found");
	    }
	}
        signature.initSign((PrivateKey) key);

        try {
	    signature.update(bytes);
	    return signature.sign();
        } catch (SignatureException se) {
	    // should never occur!
	    throw new RuntimeException(se.getMessage());
        }
    }
}
