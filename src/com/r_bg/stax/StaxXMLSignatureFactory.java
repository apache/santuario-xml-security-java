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

import java.security.AccessController;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;
import java.util.List;

import javax.xml.crypto.Data;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Manifest;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignatureProperties;
import javax.xml.crypto.dsig.SignatureProperty;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.XMLValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.DigestMethodParameterSpec;
import javax.xml.crypto.dsig.spec.SignatureMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.stream.StreamFilter;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.jcp.xml.dsig.internal.dom.XMLDSigRI;

public class StaxXMLSignatureFactory extends XMLSignatureFactory {
	static {
      
                Security.addProvider(new StaxProvider());
      
    }@Override
	public XMLSignature newXMLSignature(SignedInfo si, KeyInfo ki) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public XMLSignature newXMLSignature(SignedInfo si, KeyInfo ki, List objects, String id, String signatureValueId) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Reference newReference(String uri, DigestMethod dm) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Reference newReference(String uri, DigestMethod dm, List transforms, String type, String id) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Reference newReference(String uri, DigestMethod dm, List transforms, String type, String id, byte[] digestValue) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Reference newReference(String uri, DigestMethod dm, List appliedTransforms, Data result, List transforms, String type, String id) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SignedInfo newSignedInfo(CanonicalizationMethod cm, SignatureMethod sm, List references) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SignedInfo newSignedInfo(CanonicalizationMethod cm, SignatureMethod sm, List references, String id) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public XMLObject newXMLObject(List content, String id, String mimeType, String encoding) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Manifest newManifest(List references) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Manifest newManifest(List references, String id) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SignatureProperty newSignatureProperty(List content, String target, String id) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SignatureProperties newSignatureProperties(List properties, String id) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public DigestMethod newDigestMethod(String algorithm, DigestMethodParameterSpec params) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SignatureMethod newSignatureMethod(String algorithm, SignatureMethodParameterSpec params) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Transform newTransform(String algorithm, TransformParameterSpec params) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Transform newTransform(String algorithm, XMLStructure params) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CanonicalizationMethod newCanonicalizationMethod(String algorithm, C14NMethodParameterSpec params) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CanonicalizationMethod newCanonicalizationMethod(String algorithm, XMLStructure params) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		// TODO Auto-generated method stub
		return null;
	}

    @Override
    public XMLSignature unmarshalXMLSignature(XMLValidateContext context) 
        throws MarshalException {
        if (context == null) {
            throw new NullPointerException();
        }
        if (!(context instanceof StaxValidateContext)) {
            throw new ClassCastException();
        }
        StaxValidateContext svc = (StaxValidateContext) context;
        XMLStreamReader reader = svc.getXMLStreamReader();
        XMLInputFactory xif = XMLInputFactory.newInstance();
        StreamFilter sf = svc.getStreamFilter();
        try {
            XMLStreamReader fsr = xif.createFilteredReader(reader, sf);
              while ((fsr.getEventType()) != XMLStreamReader.END_DOCUMENT) {
                  fsr.next();
              }
        } catch (XMLStreamException xse) {
            throw new MarshalException(xse);
        }

        return svc.getSignature();
    }

    @Override
    public XMLSignature unmarshalXMLSignature(XMLStructure xmlStructure) 
        throws MarshalException {
        if (xmlStructure == null) throw new NullPointerException();
        return null;
    }

	@Override
	public boolean isFeatureSupported(String feature) {
		// TODO Auto-generated method stub
		return false;
	}

    @Override
    public URIDereferencer getURIDereferencer() {
	return StaxURIDereferencer.INSTANCE;
    }
}
