/*
 * Copyright 2005-2007 The Apache Software Foundation.
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

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * StAX-based abstract implementation of SignatureMethod.
 *
 * @author Sean Mullan
 */
public abstract class StaxSignatureMethod implements SignatureMethod, StaxWorker {

    /**
     * Creates a <code>StaxSignatureMethod</code>. 
     */
    protected StaxSignatureMethod() {} 

    static StaxSignatureMethod unmarshal(XMLStreamReader reader) 
	throws MarshalException {
        String alg = reader.getAttributeValue(null, "Algorithm");
        if (alg.equals(SignatureMethod.DSA_SHA1)) {
            return new StaxDSASignatureMethod();
        } else if (alg.equals(SignatureMethod.RSA_SHA1)) {
            return new StaxRSASignatureMethod();
	} else if (alg.equals(SignatureMethod.HMAC_SHA1)) {
            return new StaxHMACSignatureMethod();
        } else {
            throw new MarshalException("unsupported signature algorithm: " 
		+ alg);
        }
    }

    /**
     * This method invokes the abstract {@link #marshalParams marshalParams} 
     * method to marshal any algorithm-specific parameters.
     */
    public void marshal(XMLStreamWriter writer, String dsPrefix) 
	throws XMLStreamException {

	writer.writeStartElement
            (dsPrefix, XMLSignature.XMLNS, "SignatureMethod");
        writer.writeAttribute("Algorithm", getAlgorithm());

        marshalParams(writer, dsPrefix);

        writer.writeEndElement();
    }

    /**
     * Verifies the passed-in signature with the specified key, using the
     * underlying signature or MAC algorithm.
     *
     * @param key the verification key
     * @param bytes the bytes to be verified
     * @param signature the signature
     * @param context the XMLValidateContext
     * @return <code>true</code> if the signature verified successfully,
     *    <code>false</code> if not
     * @throws NullPointerException if <code>key</code>, <code>bytes</code> or
     *    <code>signature</code> are <code>null</code>
     * @throws InvalidKeyException if the key is improperly encoded, of
     *    the wrong type, or parameters are missing, etc
     * @throws SignatureException if an unexpected error occurs, such
     *    as the passed in signature is improperly encoded
     * @throws XMLSignatureException if an unexpected error occurs
     */
    public abstract boolean verify(Key key, byte[] bytes, byte[] signature,
	XMLValidateContext context) throws InvalidKeyException, SignatureException,
	XMLSignatureException;

    /**
     * Signs the bytes with the specified key, using the underlying
     * signature or MAC algorithm.
     *
     * @param key the signing key
     * @param bytes the bytes to sign
     * @param context the XMLSignContext
     * @return the signature
     * @throws NullPointerException if <code>key</code> or
     *    <code>bytes</code> are <code>null</code>
     * @throws InvalidKeyException if the key is improperly encoded, of
     *    the wrong type, or parameters are missing, etc
     * @throws XMLSignatureException if an unexpected error occurs
     */
    public abstract byte[] sign(Key key, byte[] bytes, XMLSignContext context) 
        throws InvalidKeyException, XMLSignatureException;

    /**
     * Marshals the algorithm-specific parameters to an XMLStreamWriter and
     * appends it to the specified parent element.
     *
     * @param writer the XMLStreamWriter to write the parameters to
     * @param paramsPrefix the algorithm parameters prefix to use
     * @throws XMLStreamException if the parameters cannot be marshalled
     */
    protected abstract void marshalParams(XMLStreamWriter writer, 
	String paramsPrefix) throws XMLStreamException;

    /**
     * Returns true if parameters are equal; false otherwise.
     *
     * Subclasses should override this method to compare algorithm-specific
     * parameters.
     */
    protected abstract boolean paramsEqual(AlgorithmParameterSpec spec);

    public boolean equals(Object o) {
	if (this == o) {
            return true;
	}

        if (!(o instanceof SignatureMethod)) {
            return false;
	}
        SignatureMethod osm = (SignatureMethod) o;

	return (getAlgorithm().equals(osm.getAlgorithm()) && 
	    paramsEqual(osm.getParameterSpec()));
    }

    public int hashCode() {
	return 57;
    }

    public boolean isFeatureSupported(String feature) {
	return false;
    }
}
