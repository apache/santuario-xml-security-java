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
import javax.xml.crypto.dsig.spec.HMACParameterSpec;
import javax.xml.crypto.dsig.spec.SignatureMethodParameterSpec;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.stream.events.XMLEvent;
import org.jcp.xml.dsig.internal.HmacSHA1;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.jcp.xml.dsig.internal.MacOutputStream;

/**
 * Stax-based implementation of HMAC SignatureMethod.
 *
 * @author Sean Mullan
 */
public final class StaxHMACSignatureMethod extends StaxSignatureMethod {

    private HmacSHA1 hmac = new HmacSHA1();
    private HMACParameterSpec params = null;
    private int outputLength = -1;
    private boolean readOutputLength = false;

    public String getAlgorithm() {
	return SignatureMethod.HMAC_SHA1;
    }

    public AlgorithmParameterSpec getParameterSpec() {
	return params;
    }

    public StaxWorker read(XMLStreamReader reader) {
	switch (reader.getEventType()) {
	    case XMLStreamReader.START_ELEMENT:
	        if (reader.getNamespaceURI().equals(XMLSignature.XMLNS)) {
	            String name = reader.getLocalName();
	            if (name.equals("HMACOutputLength")) {
		        readOutputLength = true;
		    }
	        }
	        break;
	    case XMLStreamReader.CHARACTERS:
		if (readOutputLength) {
		    outputLength = new Integer(reader.getText()).intValue();
		}
		params = new HMACParameterSpec(outputLength);
		break;
	    case XMLStreamReader.END_ELEMENT:
		if (reader.getNamespaceURI().equals(XMLSignature.XMLNS) &&
		    reader.getLocalName().equals("HMACOutputLength")) {
		    readOutputLength = false;
		}
		break;
	}
	return null;
    }

    public StaxWatcher remove() {
	return null;
    }

    protected void marshalParams(XMLStreamWriter writer, String prefix)
	throws XMLStreamException {

	if (params != null) {
            writer.writeStartElement(prefix, "HMACOutputLength", 
	        XMLSignature.XMLNS);
            writer.writeCharacters(String.valueOf(outputLength));

	    writer.writeEndElement();
	}
    }

    public boolean verify(Key key, byte[] bytes, byte[] sig,
	XMLValidateContext context) 
	throws InvalidKeyException, SignatureException, XMLSignatureException {
        if (key == null || bytes == null || sig == null) {
	    System.out.println("key:"+key);
	    System.out.println("bytes:"+bytes);
	    System.out.println("sig:"+sig);
            throw new NullPointerException
		("key, bytes or signature data can't be null");
        }
        hmac.init(key, outputLength);
	hmac.update(bytes);
        return hmac.verify(sig);
    }

    public byte[] sign(Key key, byte[] bytes, XMLSignContext context) 
	throws InvalidKeyException, XMLSignatureException {
        if (key == null || bytes == null) {
            throw new NullPointerException();
        }
        hmac.init(key, outputLength);
	hmac.update(bytes);

        try {
            return hmac.sign();
        } catch (SignatureException se) {
            // should never occur!
            throw new RuntimeException(se.getMessage());
        }
    }

    public boolean paramsEqual(AlgorithmParameterSpec spec) {
	if (getParameterSpec() == spec) {
	    return true;
	}
        if (!(spec instanceof HMACParameterSpec)) {
	    return false;
	}
	HMACParameterSpec ospec = (HMACParameterSpec) spec;

	return (outputLength == ospec.getOutputLength());
    }
}
