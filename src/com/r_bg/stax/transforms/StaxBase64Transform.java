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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import javax.xml.crypto.Data;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.crypto.dsig.TransformService;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.stream.XMLStreamReader;

import org.apache.xml.security.utils.Base64;
import com.r_bg.stax.StaxData;

/**
 * Stax-based implementation of Base64 Decode TransformService.
 *
 * @author Sean Mullan
 */
public class StaxBase64Transform extends TransformService {

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
	byte[] bytes = null;
	XMLStreamReader reader = ((StaxData) data).getXMLStreamReader();
        switch (reader.getEventType()) {
            case XMLStreamReader.CHARACTERS:
		String text = reader.getText();
		try {
	            bytes = Base64.decode(text);
		} catch (Exception e) {
		    throw new TransformException(e);
		}
	        break;
        }
	return new OctetStreamData(new ByteArrayInputStream(bytes));
    }

    public Data transform(Data data, XMLCryptoContext context, OutputStream os)
	throws TransformException {
	if (data instanceof StaxData) {
	    XMLStreamReader reader = ((StaxData) data).getXMLStreamReader();
            switch (reader.getEventType()) {
                case XMLStreamReader.CHARACTERS:
		    String text = reader.getText();
		    try {
	                Base64.decode(text, os);
		    } catch (Exception e) {
		        throw new TransformException(e);
		    }
	            break;
            }
	    return null;
	} else if (data instanceof OctetStreamData) {
	    InputStream is = ((OctetStreamData) data).getOctetStream();
	    try {
		Base64.decode(is, os);
	    } catch (Exception e) {
	        throw new TransformException(e);
	    }
	    return null;
	} else {
	    throw new TransformException("Unrecognized data type");
	}
    }

    public AlgorithmParameterSpec getParameterSpec() {
	return null;
    }

    public boolean isFeatureSupported(String feature) {
	return false;
    }
}
