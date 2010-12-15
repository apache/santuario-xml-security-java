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

import java.security.Key;
import java.util.HashMap;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLValidateContext;
import javax.xml.stream.StreamFilter;
import javax.xml.stream.XMLStreamReader;

public class StaxValidateContext implements XMLValidateContext {	
    private XMLStreamReader reader;
    private int signatureNumber = 0;
    private StaxSignatureValidator sig;
    private KeySelector ks;
    private HashMap nsMap = new HashMap();
    private HashMap objMap = new HashMap();
    private HashMap propMap = new HashMap();
    private String baseURI;
    private String defaultPrefix;
    private URIDereferencer dereferencer;

	public static StaxValidateContext createEnvolopedValidator(Key key, XMLStreamReader reader) {		
		return new StaxValidateContext(key,reader);
	}
	public void setSignatureNumber(int number) {
		signatureNumber=number;
	}
	
    public StaxValidateContext(Key key, XMLStreamReader reader) {
	if (key == null || reader == null) {
	    throw new NullPointerException();
	}
	setKeySelector(KeySelector.singletonKeySelector(key));
	this.reader = reader;		
	sig = new StaxSignatureValidator(this);
    }

    public StaxValidateContext(KeySelector ks, XMLStreamReader reader) {
	if (ks == null || reader == null) {
	    throw new NullPointerException();
	}
	this.ks = ks;
	this.reader = reader;		
	sig = new StaxSignatureValidator(this);
    }
	
    public String getBaseURI() {
	return baseURI;
    }

    public void setBaseURI(String baseURI) {
        if (baseURI != null) {
            java.net.URI.create(baseURI);
        }
        this.baseURI = baseURI;
    }

    public KeySelector getKeySelector() {
	return ks;
    }

    public void setKeySelector(KeySelector ks) {
	this.ks = ks;
    }

    public URIDereferencer getURIDereferencer() {
	return dereferencer;
    }

    public void setURIDereferencer(URIDereferencer dereferencer) {
        this.dereferencer = dereferencer;
    }

    public String getNamespacePrefix(String namespaceURI, 
	String defaultPrefix) {
        if (namespaceURI == null) {
            throw new NullPointerException("namespaceURI cannot be null");
        }
        String prefix = (String) nsMap.get(namespaceURI);
        return (prefix != null ? prefix : defaultPrefix);
    }

    public String putNamespacePrefix(String namespaceURI, String prefix) {
        if (namespaceURI == null) {
            throw new NullPointerException("namespaceURI is null");
        }
        return (String) nsMap.put(namespaceURI, prefix);
    }

    public String getDefaultNamespacePrefix() {
	return defaultPrefix;
    }

    public void setDefaultNamespacePrefix(String defaultPrefix) {
	this.defaultPrefix = defaultPrefix;
    }

    public Object setProperty(String name, Object value) {
        if (name == null) {
            throw new NullPointerException("name is null");
        }
        return propMap.put(name, value);
    }

    public Object getProperty(String name) {
        if (name == null) {
            throw new NullPointerException("name is null");
        }
        return propMap.get(name);
    }

    public Object get(Object key) {
        return objMap.get(key);
    }

    public Object put(Object key, Object value) {
        return objMap.put(key, value);
    }

    public XMLStreamReader getXMLStreamReader() {
	return reader;
    }

	public StreamFilter getStreamFilter() {
		return sig;
	}

	protected XMLSignature getSignature() {
		return sig.signatures.get(signatureNumber);
	}
}
