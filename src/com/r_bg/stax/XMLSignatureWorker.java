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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.Data;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyName;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.RetrievalMethod;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import com.r_bg.stax.c14n.StaxCanonicalizationMethod;
import com.r_bg.stax.transforms.StaxTransform;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.apache.xml.security.utils.DigesterOutputStream;

class Constants {
	public static final String DS_URI="http://www.w3.org/2000/09/xmldsig#";
}

class ReferenceWorker implements StaxWorker, Reference, DigestResultListener {	
	boolean readDigestValue=false;
	String uri;
	String c14nType;
	String digestMethod;
	byte[] digestValue;
	byte[] calculateDigestValue;
	boolean correct=false;
	DigesterOutputStream os;
	private String id;
	private String type;
	List<Transform> transforms = new ArrayList<Transform>();
	private XMLCryptoContext context;
	ReferenceWorker(XMLCryptoContext context) {
	    this.context = context;
	}
	public StaxWorker read(XMLStreamReader reader) {
		switch (reader.getEventType()) {
		
		case XMLStreamReader.START_ELEMENT: 
			if(Constants.DS_URI.equals(reader.getNamespaceURI())) {
			  String name=reader.getLocalName();
			  if (name.equals("Reference") ) {
				uri=reader.getAttributeValue(null,"URI");
				id=reader.getAttributeValue(null,"Id");
				type=reader.getAttributeValue(null,"Type");
			  }
			  if (name.equals("DigestMethod")) {
				digestMethod=reader.getAttributeValue(null,"Algorithm");				 
				try {
					MessageDigest ms = MessageDigest.getInstance(
							JCEMapper.translateURItoJCEID(digestMethod));
					os=new DigesterOutputStream(ms);
				} catch (NoSuchAlgorithmException e) {
					//TODO: Better error handling.
					e.printStackTrace();
				}				
			  }
			  if (name.equals("DigestValue")) {
				readDigestValue=true;
			  }			
			  if (name.equals("Transform")) {
				StaxTransform t = new StaxTransform();
				transforms.add(t);
				return t;			
			  }
			}
			break;
		case XMLStreamReader.END_ELEMENT: 
		    if (Constants.DS_URI.equals(reader.getNamespaceURI())) {
			  if (reader.getLocalName().equals("DigestValue")) {
				readDigestValue=false;
			  }
		    }
		    break;
		case XMLStreamReader.CHARACTERS:		
			if (readDigestValue) {
				try {
					digestValue=Base64.decode(reader.getText());
				} catch (Base64DecodingException e) {
					e.printStackTrace();
				}
		     }
			break;
		}
		return null;
	}
	public StaxWatcher remove() {		
	    String baseURI = context.getBaseURI();
	    if (uri != null) {
		if (uri.startsWith("#")) {
		    return new IdWatcher(uri.substring(1), this, transforms, os);
//		    return new IdWatcher(uri.substring(1),this,transforms,System.out);
		} else {
        	    // use user-specified URIDereferencer if specified; 
		    // otherwise use deflt
		    URIDereferencer ud = context.getURIDereferencer();
		    if (ud == null) {
            	        ud = StaxURIDereferencer.INSTANCE;
		    } 
		    try {
		        Data data = ud.dereference(this, context);
                       	for (Transform t : transforms) {
                       	    // Only one Transform supported right now
			    if (data instanceof StaxData) {
			        XMLStreamReader re = 
				    ((StaxData) data).getXMLStreamReader();
			        while (re.getEventType() 
				    != XMLStreamReader.END_DOCUMENT) {
                       	    	    t.transform(data, null, os);
				    re.next();
				}
			    } else {
               	    	        data = t.transform(data, null, os);
			    }
		            break;
		        }
			if (data instanceof OctetStreamData) {
			    InputStream is = 
				((OctetStreamData) data).getOctetStream();
         		    byte buf[] = new byte[1024];
         		    int read = 0;
         		    while ((read = is.read(buf)) >= 0) {
            		        os.write(buf, 0, read);
         		    }
			}
		    } catch (Exception e) {
			e.printStackTrace();
		    }
		}
		setResult(null);
	    }
	    return null;
	}

	/* (non-Javadoc)
	 * @see com.r_bg.stax.DigestResultListener#setResult(byte[])
	 */
	public void setResult(byte[] result) {
		calculateDigestValue=os.getDigestValue();
		correct=Arrays.equals(calculateDigestValue, digestValue);
		
	}
	public List getTransforms() {
		return Collections.unmodifiableList(transforms);
	}
	public DigestMethod getDigestMethod() {
		return new DigestMethod() {
			public AlgorithmParameterSpec getParameterSpec() {
				return null;
			}
			public String getAlgorithm() {
				return digestMethod;
			}
			public boolean isFeatureSupported(String feature) {
				return false;
			}
		};
	}
	public String getId() {
		return id;
	}
	public byte[] getDigestValue() {
		return digestValue == null ? null : (byte[]) digestValue.clone();
	}
	public byte[] getCalculatedDigestValue() {
		return calculateDigestValue == null ? null : (byte[]) calculateDigestValue.clone();
	}
	public boolean validate(XMLValidateContext validateContext) throws XMLSignatureException {
		return correct;
	}
	public Data getDereferencedData() {
		// TODO Auto-generated method stub
		return null;
	}
	public InputStream getDigestInputStream() {
		// TODO Auto-generated method stub
		return null;
	}
	public String getURI() {
		return uri;
	}
	public String getType() {
		return type;
	}
	public boolean isFeatureSupported(String feature) {
		return false;
	}
}

class SignedInfoWorker implements StaxWorker, SignedInfo, DigestResultListener {
	ByteArrayOutputStream bos=new ByteArrayOutputStream(); 
	byte[] canonData;
	boolean initial=true;
	C14nWorker c14n=new C14nWorker(this, bos, false);
//	C14nWorker c14n=new C14nWorker(this, System.out, false);
	List<ReferenceWorker> references=new ArrayList<ReferenceWorker>();
	StaxSignatureMethod signatureMethod;
	StaxCanonicalizationMethod c14nMethod;
	private String id;
	private XMLCryptoContext context;
	SignedInfoWorker(XMLCryptoContext context) {
	    this.context = context;
	}
	public StaxWorker read(XMLStreamReader reader) {
		if (reader.getEventType()==XMLStreamReader.START_ELEMENT && Constants.DS_URI.equals(reader.getNamespaceURI())) {
			String name=reader.getLocalName();
			if (name.equals("SignedInfo") ) {
				id=reader.getAttributeValue(null,"Id");
			} else if (name.equals("Reference") ) {
				ReferenceWorker r=new ReferenceWorker(context);
				references.add(r);
				return r;			
			} else if (name.equals("SignatureMethod")) {
				try {
				    signatureMethod = StaxSignatureMethod.unmarshal(reader);
				    return signatureMethod;
				} catch (MarshalException me) {
				    me.printStackTrace();
				}
			} else if (name.equals("CanonicalizationMethod")) {
				c14nMethod = new StaxCanonicalizationMethod();
				return c14nMethod;
			}
		}
		if (initial) {
			initial=false;
			return c14n;
		}
		
		return null;
	}

	public StaxWatcher remove() {
		canonData = bos.toByteArray();
		return null;
	}

	public CanonicalizationMethod getCanonicalizationMethod() {
		return c14nMethod;
	}

	public SignatureMethod getSignatureMethod() {
		return signatureMethod;
	}

	public List getReferences() {
		return Collections.unmodifiableList(references);
	}

	public String getId() {
		return id;
	}

	public InputStream getCanonicalizedData() {
		return new ByteArrayInputStream(canonData);
	}

	public boolean isFeatureSupported(String feature) {
		return false;
	}

	public void setResult(byte[] result) {		
		
	}
	
}
class SignatureWatcher implements StaxWatcher {	
    private StaxValidateContext context;
    SignatureWatcher(StaxValidateContext context) {
	this.context = context;
    }
    public StaxWorker watch(XMLStreamReader reader, StaxSignatureValidator sig) {
	String name=reader.getLocalName();
	String uri=reader.getNamespaceURI();
	if (name.equals("Signature") && uri.equals(XMLSignature.XMLNS)) {
	    XMLSignatureWorker s = new XMLSignatureWorker(context);
	    sig.addSignature(s);
	    return s;
	}
		
	return null;
    }
}

class SignatureValueWorker implements StaxWorker,XMLSignature.SignatureValue {		
    private String id;
    byte[] signatureValue;
    boolean isValid=false;
    private boolean readSignatureValue = false;
    private StringBuffer buf = new StringBuffer();

    public StaxWorker read(XMLStreamReader reader) {
	switch (reader.getEventType()) {
	  case XMLStreamReader.START_ELEMENT:
	    if (Constants.DS_URI.equals(reader.getNamespaceURI())) {
		String name=reader.getLocalName();
		if (name.equals("SignatureValue") ) {
		    id=reader.getAttributeValue(null,"Id");
		    readSignatureValue = true;
		}
	    }
	    break;
	  case XMLStreamReader.END_ELEMENT:
	    if (Constants.DS_URI.equals(reader.getNamespaceURI()) &&
		reader.getLocalName().equals("SignatureValue")) {
		readSignatureValue = false;
	 	try {
	            signatureValue = Base64.decode(buf.toString());
		} catch (Base64DecodingException e) {
		    e.printStackTrace();
		}
	    }
	    break;
	  case XMLStreamReader.CHARACTERS:
	    if (readSignatureValue) {
		buf = buf.append(reader.getText());
	    }
	    break;
	}
	return null;
    }

    public StaxWatcher remove() {		
	return null;
    }

    public boolean isFeatureSupported(String feature) {
	return false;
    }

    public String getId() {
        return id;
    }

    public byte[] getValue() {
        return (byte[]) signatureValue.clone();
    }

    public boolean validate(XMLValidateContext validateContext) throws XMLSignatureException {
        //FIXME: only returns cached status
        return isValid;
    }
}

class KeyValueWorker implements StaxWorker, KeyValue {		
    private boolean isDSA = false;
    private PublicKey key;
    private BigInteger p, q, g, y, mod, exp;
    private boolean startDSA, startRSA;
    private StringBuffer buf = new StringBuffer();

    public StaxWorker read(XMLStreamReader reader) {
	switch (reader.getEventType()) {
	    case XMLStreamReader.START_ELEMENT: 
		if(Constants.DS_URI.equals(reader.getNamespaceURI())) {
	            String name = reader.getLocalName();
	            if (name.equals("DSAKeyValue")) {
		        isDSA = true;
			startDSA = true;
	            } else if (name.equals("RSAKeyValue")) {
		        isDSA = false;
			startRSA = true;
	            } 
		}
		break;
	    case XMLStreamReader.END_ELEMENT: 
		if(Constants.DS_URI.equals(reader.getNamespaceURI())) {
		    try {
	            String name = reader.getLocalName();
	            if (name.equals("DSAKeyValue")) {
		        startDSA = false;
	            } else if (name.equals("RSAKeyValue")) {
		        startRSA = false;
	            } else if (name.equals("Modulus")) {
		        mod = new BigInteger(1, Base64.decode(buf.toString()));
	            } else if (name.equals("Exponent")) {
		        exp = new BigInteger(1, Base64.decode(buf.toString()));
	            } else if (name.equals("P")) {
		        p = new BigInteger(1, Base64.decode(buf.toString()));
	            } else if (name.equals("Q")) {
		        q = new BigInteger(1, Base64.decode(buf.toString()));
	            } else if (name.equals("G")) {
		        g = new BigInteger(1, Base64.decode(buf.toString()));
	            } else if (name.equals("Y")) {
		        y = new BigInteger(1, Base64.decode(buf.toString()));
		    }
	            } catch (Base64DecodingException e) {
		        e.printStackTrace();
		    }
		    buf = new StringBuffer();
		}
		break;
	    case XMLStreamReader.CHARACTERS:
		if (startDSA || startRSA) {
		    buf = buf.append(reader.getText());
		}
		break;
	}
	return null;
    }
		
    public StaxWatcher remove() {
	return null;
    }
    public PublicKey getPublicKey() throws KeyException {
	if (key == null) {
	    try {
		if (isDSA) {
	            KeyFactory kf = KeyFactory.getInstance("DSA");
	            DSAPublicKeySpec spec = new DSAPublicKeySpec(y, p, q, g);
	            key = kf.generatePublic(spec);
		} else {
	            KeyFactory kf = KeyFactory.getInstance("RSA");
	            RSAPublicKeySpec spec = new RSAPublicKeySpec(mod, exp);
	            key = kf.generatePublic(spec);
		}
	    } catch (Exception e) {
		throw new KeyException(e);
	    }
	}
	return key;
	
    }
    public boolean isFeatureSupported(String feature) {
	return false;
    }
}

class X509DataWorker implements StaxWorker, X509Data {		
    private List content = new ArrayList();
    private CertificateFactory cf; 
    private boolean readSN, readSki, readISName, readSerial, readCert, readCRL;
    private String issuer;

    public StaxWorker read(XMLStreamReader reader) {
	switch (reader.getEventType()) {
	    case XMLStreamReader.START_ELEMENT: 
		if(Constants.DS_URI.equals(reader.getNamespaceURI())) {
		    String name = reader.getLocalName();
		    if (name.equals("X509SubjectName")) {
			readSN = true;
		    } else if (name.equals("X509SKI")) {
			readSki = true;
		    } else if (name.equals("X509IssuerName")) {
			readISName = true;
		    } else if (name.equals("X509IssuerSerial")) {
			readSerial = true;
		    } else if (name.equals("X509Certificate")) {
			readCert = true;
		    } else if (name.equals("X509CRL")) {
			readCRL = true;
		    }
		}
		break;
	    case XMLStreamReader.CHARACTERS:
		String text = reader.getText();
		if (readSN) {
		    content.add(text);
		    readSN = false;
		} else if (readISName) {
		    issuer = text;
		    readISName = false;
		} else if (readSerial) {
		    byte[] bytes = null;
		    try {
			bytes = Base64.decode(text);
		    } catch (Base64DecodingException e) {
			e.printStackTrace();
		    }
		    final BigInteger serial = new BigInteger(1, bytes);
	            content.add(new X509IssuerSerial() {
		        public String getIssuerName() {
		            return issuer;
		        }
		        public BigInteger getSerialNumber() {
		            return serial;
		        }
		        public boolean isFeatureSupported(String feature) {
		            return false;
		        }
		    });
		    readSerial = false;
		} else if (readSki) {
		    try {
		        byte[] ski = Base64.decode(text);
		        content.add(ski);
		    } catch (Base64DecodingException e) {
		        e.printStackTrace();
		    }
		    readSki = false;
		} else if (readCert) {
		    try {
		        byte[] cert = Base64.decode(text);
		        if (cf == null) {
    			    cf = CertificateFactory.getInstance("X.509");
		        }
		        content.add(cf.generateCertificate
			    (new ByteArrayInputStream(cert)));
		    } catch (Exception e) {
		        e.printStackTrace();
		    }
		    readCert = false;
		} else if (readCRL) {
		    try {
		        byte[] crl = Base64.decode(text);
		        if (cf == null) {
    			    cf = CertificateFactory.getInstance("X.509");
		        }
		        content.add
			    (cf.generateCRL(new ByteArrayInputStream(crl)));
		    } catch (Exception e) {
		        e.printStackTrace();
		    }
		    readCRL = false;
		}
		break;
	}
	return null;
    }
    public StaxWatcher remove() {
	return null;
    }
    public List getContent() {
	return Collections.unmodifiableList(content);
    }
    public boolean isFeatureSupported(String feature) {
	return false;
    }
}

class RetrievalMethodWorker implements StaxWorker, RetrievalMethod {
    private String uri, type;
    private List<Transform> transforms = new ArrayList<Transform>();
    public StaxWorker read(XMLStreamReader reader) {
	switch (reader.getEventType()) {
	    case XMLStreamReader.START_ELEMENT: 
		if(Constants.DS_URI.equals(reader.getNamespaceURI())) {
		    String name = reader.getLocalName();
		    if (name.equals("RetrievalMethod") ) {
			uri = reader.getAttributeValue(null, "URI");
			type = reader.getAttributeValue(null, "Type");
		    } else if (name.equals("Transform")) {
			StaxTransform t = new StaxTransform();
			transforms.add(t);
			return t;
		    }
		}
		break;
	}
        return null;
    }
    public StaxWatcher remove() {
	return null;
    }
    public List getTransforms() {
	return Collections.unmodifiableList(transforms);
    }
    public String getType() {
	return type;
    }
    public String getURI() {
	return uri;
    }
    public Data dereference(XMLCryptoContext context) {
	throw new UnsupportedOperationException();
    }
    public boolean isFeatureSupported(String feature) {
        return false;
    }
}
			
class KeyInfoWorker implements StaxWorker, KeyInfo {		
    private String id;
    private List content = new ArrayList();
    private boolean readKeyName = false;
    public StaxWorker read(XMLStreamReader reader) {
	switch (reader.getEventType()) {
	    case XMLStreamReader.START_ELEMENT: 
		if(Constants.DS_URI.equals(reader.getNamespaceURI())) {
		    String name = reader.getLocalName();
		    if (name.equals("KeyInfo") ) {
			id = reader.getAttributeValue(null, "Id");
		    } else if (name.equals("KeyName") ) {
			readKeyName = true;
		    } else if (name.equals("KeyValue") ) {
			KeyValueWorker kv = new KeyValueWorker();
			content.add(kv);
			return kv;
		    } else if (name.equals("RetrievalMethod") ) {
			RetrievalMethodWorker rm = new RetrievalMethodWorker();
			content.add(rm);
			return rm;
		    } else if (name.equals("X509Data") ) {
			X509DataWorker xd = new X509DataWorker();
			content.add(xd);
			return xd;
		    }
		}
		break;
	    case XMLStreamReader.CHARACTERS:
		if (readKeyName) {
		    final String keyName = reader.getText();
		    content.add(new KeyName() {
		        public String getName() {
			    return keyName;
		        }
		        public boolean isFeatureSupported(String feature) {
			    return false;
		        }
		    });
		    readKeyName = false;
		}
		break;
	}
	return null;
    }
    public StaxWatcher remove() {
	return null;
    }
    public List getContent() {
	return Collections.unmodifiableList(content);
    }
    public String getId() {
	return id;
    }
    public void marshal(XMLStructure parent, XMLCryptoContext context) throws MarshalException {
	throw new UnsupportedOperationException();
    }
    public boolean isFeatureSupported(String feature) {
	return false;
    }
}

class SignaturePropertiesWorker implements StaxWorker, SignatureProperties {
    private String id;
    private List<SignatureProperty> props = new ArrayList<SignatureProperty>();

    public StaxWorker read(XMLStreamReader reader) {
	switch (reader.getEventType()) {
	    case XMLStreamReader.START_ELEMENT: 
		if(Constants.DS_URI.equals(reader.getNamespaceURI())) {
		    String name = reader.getLocalName();
		    if (name.equals("SignatureProperties") ) {
			id = reader.getAttributeValue(null, "Id");
		    } else if (name.equals("SignatureProperty")) {
			final String id = reader.getAttributeValue(null, "Id");
			final String target = reader.getAttributeValue(null, "Target");
			props.add(new SignatureProperty() {
			    public String getId() {
				return id;
			    }
			    public String getTarget() {
				return target;
			    }
			    public List getContent() {
				// FIXME
				return null;
			    }
			    public boolean isFeatureSupported(String feature) {
				return false;
			    }
			});
		    }
		}
		break;
	}
	return null;
    }
    public StaxWatcher remove() {
	return null;
    }
    public String getId() {
	return id;
    }
    public List getProperties() {
	return Collections.unmodifiableList(props);
    }
    public boolean isFeatureSupported(String feature) {
	return false;
    }
}

class ManifestWorker implements StaxWorker, Manifest {		
    private String id;
    private List<Reference> refs = new ArrayList<Reference>();
    private XMLCryptoContext context;
    ManifestWorker(XMLCryptoContext context) {
	this.context = context;
    }
    public StaxWorker read(XMLStreamReader reader) {
	switch (reader.getEventType()) {
	    case XMLStreamReader.START_ELEMENT: 
		if(Constants.DS_URI.equals(reader.getNamespaceURI())) {
		    String name = reader.getLocalName();
		    if (name.equals("Manifest") ) {
			id = reader.getAttributeValue(null, "Id");
		    } else if (name.equals("Reference")) {
			ReferenceWorker rw = new ReferenceWorker(context);
			refs.add(rw);
			return rw;
		    }
		}
		break;
	}
	return null;
    }
    public StaxWatcher remove() {
	return null;
    }
    public String getId() {
	return id;
    }
    public List getReferences() {
	return Collections.unmodifiableList(refs);
    }
    public boolean isFeatureSupported(String feature) {
	return false;
    }
}

class XMLObjectWorker implements StaxWorker, XMLObject {		
    private String id;
    private String mimeType;
    private String encoding;
    private List<XMLStructure> content = new ArrayList<XMLStructure>();
    private XMLCryptoContext context;
    XMLObjectWorker(XMLCryptoContext context) {
	this.context = context;
    }
    public StaxWorker read(XMLStreamReader reader) {
	switch (reader.getEventType()) {
	    case XMLStreamReader.START_ELEMENT: 
		if(Constants.DS_URI.equals(reader.getNamespaceURI())) {
		    String name = reader.getLocalName();
		    if (name.equals("Object")) {
			id = reader.getAttributeValue(null, "Id");
			mimeType = reader.getAttributeValue(null, "MimeType");
			encoding = reader.getAttributeValue(null, "Encoding");
		    } else if (name.equals("Manifest")) {
			ManifestWorker mw = new ManifestWorker(context);
			content.add(mw);
			return mw;
		    } else if (name.equals("SignatureProperties")) {
			SignaturePropertiesWorker spw = new SignaturePropertiesWorker();
			content.add(spw);
			return spw;
		    } else if (name.equals("X509Data")) {
			X509DataWorker xw = new X509DataWorker();
			content.add(xw);
			return xw;
		    }
		}
		break;
	}
	return null;
    }
    public StaxWatcher remove() {
	return null;
    }
    public List getContent() {
	return Collections.unmodifiableList(content);
    }
    public String getId() {
	return id;
    }
    public String getMimeType() {
	return mimeType;
    }
    public String getEncoding() {
	return encoding;
    }
    public boolean isFeatureSupported(String feature) {
	return false;
    }
}

public class XMLSignatureWorker implements StaxWorker,XMLSignature {		
	private SignedInfoWorker si;
	private SignatureValueWorker sv;
	private KeyInfoWorker ki;
	private String id;
	private List<XMLObject> xmlObjects = new ArrayList<XMLObject>();
	private KeySelectorResult ksr;
	private XMLCryptoContext context;
	XMLSignatureWorker(XMLCryptoContext context) {
	    this.context = context;
	}
	public StaxWorker read(XMLStreamReader reader) {
		switch (reader.getEventType()) {
		  case XMLStreamReader.START_ELEMENT:
			if (Constants.DS_URI.equals(reader.getNamespaceURI())) {
				String name=reader.getLocalName();
				if (name.equals("Signature") ) {
					id=reader.getAttributeValue(null,"Id");
				} else if (name.equals("SignedInfo") ) {
					si=new SignedInfoWorker(context);
					return si;			
				} else if (name.equals("SignatureValue")) {
					sv=new SignatureValueWorker();
					return sv;
				} else if (name.equals("Object")) {
					XMLObjectWorker xo=new XMLObjectWorker(context);
					xmlObjects.add(xo);
					return xo;
				} else if (name.equals("KeyInfo")) {
					ki=new KeyInfoWorker();
					return ki;
				}			
			}
			break;
	    	}
		return null;
	}
	
	public StaxWatcher remove() {		
		return null;
	}
	public boolean validate(XMLValidateContext validateContext) throws XMLSignatureException {
		if (validateContext == null) throw new NullPointerException();
		StaxValidateContext ctx=(StaxValidateContext) validateContext;
		try {
			// get key from KeySelector
                        try {
                            ksr = ctx.getKeySelector().select(getKeyInfo(), 
				KeySelector.Purpose.VERIFY, 
				getSignedInfo().getSignatureMethod(), 
				validateContext);
                        } catch (KeySelectorException kse) {
                            throw new XMLSignatureException(kse);
                        }
			boolean isSignatureValid = si.signatureMethod.verify
			    (ksr.getKey(), si.canonData, sv.signatureValue, 
			     validateContext);
			sv.isValid = isSignatureValid;
			if (!isSignatureValid) return false;
			for (Reference ref: si.references) {
				if (!ref.validate(ctx))
					return false;
			}
			return true;
		} catch (Exception e) {
			throw new XMLSignatureException(e);
		}
	}
	public KeyInfo getKeyInfo() {
		return ki;
	}
	public SignedInfo getSignedInfo() {
		return si;
	}
	public List getObjects() {
		return Collections.unmodifiableList(xmlObjects);
	}
	public String getId() {
		return id;
	}
	public SignatureValue getSignatureValue() {
		return sv;
	}
	public void sign(XMLSignContext signContext) throws MarshalException, XMLSignatureException {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException();
	}
	public KeySelectorResult getKeySelectorResult() {
		return ksr;
	}
	public boolean isFeatureSupported(String feature) {
		return false;
	}
}
