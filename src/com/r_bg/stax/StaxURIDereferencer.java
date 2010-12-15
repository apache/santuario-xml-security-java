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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URLConnection;
import java.net.URL;
import javax.xml.crypto.Data;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;

/**
 * A STaX based implementation of URIDereferencer.
 *
 * Currently, only http and file URIs are supported.
 *
 * @author Sean Mullan
 */
public class StaxURIDereferencer implements URIDereferencer {

    static final StaxURIDereferencer INSTANCE = new StaxURIDereferencer();

    public Data dereference(URIReference uriReference, XMLCryptoContext context)
	throws URIReferenceException {
	if (uriReference == null || context == null) {
	    throw new NullPointerException();
	}
	String uri = uriReference.getURI();
	String baseURI = context.getBaseURI();
	if (uri.startsWith("http:") || 
	    (baseURI != null && baseURI.startsWith("http:"))) {
	    try {
                URLConnection uc = null;
                if (baseURI != null) {
                    uc = new URL(new URL(baseURI), uri).openConnection();
                } else { 
                    uc = new URL(uri).openConnection();
                }   
                return new OctetStreamData(uc.getInputStream());
	    } catch (IOException ioe) {
		throw new URIReferenceException(ioe);
	    }
        } else if (uri.startsWith("file:") ||
            (baseURI != null && baseURI.startsWith("file:"))) {
            try {
                URI fileURI = null;
                if (baseURI != null) {
                    fileURI = new URI(baseURI).resolve(uri);
                } else {
                    fileURI = new URI(uri);
                }
                FileInputStream fs = new FileInputStream(new File(fileURI));
                XMLInputFactory xif = XMLInputFactory.newInstance();
                XMLStreamReader re = xif.createXMLStreamReader(fs);
		return new StaxData(re);
	    } catch (Exception e) {
		throw new URIReferenceException(e);
	    }
	}    

	throw new UnsupportedOperationException();
    }
}
