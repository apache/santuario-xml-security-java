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
/*
 * $Id$
 */
package org.apache.jcp.xml.dsig.internal.dom;

import javax.xml.crypto.*;
import javax.xml.crypto.dom.DOMCryptoContext;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.keyinfo.KeyValue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.apache.xml.security.utils.ClassLoaderUtils;

/**
 * DOM-based implementation of KeyValue.
 *
 * @author Sean Mullan
 */
public abstract class DOMKeyValue extends DOMStructure implements KeyValue {

    private static final String XMLDSIG_11_XMLNS 
        = "http://www.w3.org/2009/xmldsig11#";
    private final PublicKey publicKey;

    public DOMKeyValue(PublicKey key) throws KeyException {
        if (key == null) {
            throw new NullPointerException("key cannot be null");
        }
        this.publicKey = key;
    }

    /**
     * Creates a <code>DOMKeyValue</code> from an element.
     *
     * @param kvtElem a KeyValue child element
     */
    public DOMKeyValue(Element kvtElem) throws MarshalException {
        this.publicKey = unmarshalKeyValue(kvtElem);
    }

    static KeyValue unmarshal(Element kvElem) throws MarshalException {
        Element kvtElem = DOMUtils.getFirstChildElement(kvElem);
        if (kvtElem == null) {
            throw new MarshalException("KeyValue must contain at least one type");
        }
        
        String namespace = kvtElem.getNamespaceURI();
        if (kvtElem.getLocalName().equals("DSAKeyValue") && XMLSignature.XMLNS.equals(namespace)) {
            return new DSA(kvtElem);
        } else if (kvtElem.getLocalName().equals("RSAKeyValue") && XMLSignature.XMLNS.equals(namespace)) {
            return new RSA(kvtElem);
        } else if (kvtElem.getLocalName().equals("ECKeyValue") && XMLDSIG_11_XMLNS.equals(namespace)) {
            return new EC(kvtElem);
        } else {
            return new Unknown(kvtElem);
        }
    }

    public PublicKey getPublicKey() throws KeyException {
        if (publicKey == null) {
            throw new KeyException("can't convert KeyValue to PublicKey");
        } else {
            return publicKey;
        }
    }

    public void marshal(Node parent, String dsPrefix, DOMCryptoContext context)
        throws MarshalException
    {
        Document ownerDoc = DOMUtils.getOwnerDocument(parent);

        // create KeyValue element
        Element kvElem = DOMUtils.createElement(ownerDoc, "KeyValue",
                                                XMLSignature.XMLNS, dsPrefix);
        marshalPublicKey(kvElem, ownerDoc, dsPrefix, context);

        parent.appendChild(kvElem);
    }

    abstract void marshalPublicKey(Node parent, Document doc, String dsPrefix, 
        DOMCryptoContext context) throws MarshalException;

    abstract PublicKey unmarshalKeyValue(Element kvtElem) 
        throws MarshalException;

    private static PublicKey generatePublicKey(KeyFactory kf, KeySpec keyspec) {
        try {
            return kf.generatePublic(keyspec);
        } catch (InvalidKeySpecException e) {
            //@@@ should dump exception to log
            return null;
        }
    }
 
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof KeyValue)) {
            return false;
        }
        try {
            KeyValue kv = (KeyValue)obj;
            if (publicKey == null ) {
                if (kv.getPublicKey() != null) {
                    return false;
                }
            } else if (!publicKey.equals(kv.getPublicKey())) {
                return false;
            }
        } catch (KeyException ke) {
            // no practical way to determine if the keys are equal
            return false;
        }
        
        return true;
    }

    @Override
    public int hashCode() {
        int result = 17;
        if (publicKey != null) {
            result = 31 * result + publicKey.hashCode();
        }
        
        return result;
    }
    
    static final class RSA extends DOMKeyValue {
        // RSAKeyValue CryptoBinaries
        private DOMCryptoBinary modulus, exponent;
        private KeyFactory rsakf;

        RSA(PublicKey key) throws KeyException {
            super(key);
            RSAPublicKey rkey = (RSAPublicKey)key;
            exponent = new DOMCryptoBinary(rkey.getPublicExponent());
            modulus = new DOMCryptoBinary(rkey.getModulus());
        }

        RSA(Element elem) throws MarshalException {
            super(elem);
        }

        void marshalPublicKey(Node parent, Document doc, String dsPrefix, 
            DOMCryptoContext context) throws MarshalException {
            Element rsaElem = DOMUtils.createElement(doc, "RSAKeyValue",
                                                     XMLSignature.XMLNS,
                                                     dsPrefix);
            Element modulusElem = DOMUtils.createElement(doc, "Modulus",
                                                         XMLSignature.XMLNS,
                                                         dsPrefix);
            Element exponentElem = DOMUtils.createElement(doc, "Exponent",
                                                          XMLSignature.XMLNS,
                                                          dsPrefix);
            modulus.marshal(modulusElem, dsPrefix, context);
            exponent.marshal(exponentElem, dsPrefix, context);
            rsaElem.appendChild(modulusElem);
            rsaElem.appendChild(exponentElem);
            parent.appendChild(rsaElem);
        }

        PublicKey unmarshalKeyValue(Element kvtElem)
            throws MarshalException
        {
            if (rsakf == null) {
                try {
                    rsakf = KeyFactory.getInstance("RSA");
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException
                        ("unable to create RSA KeyFactory: " + e.getMessage());
                }
            }
            Element modulusElem = DOMUtils.getFirstChildElement(kvtElem,
                                                                "Modulus",
                                                                XMLSignature.XMLNS);
            modulus = new DOMCryptoBinary(modulusElem.getFirstChild());
            Element exponentElem = DOMUtils.getNextSiblingElement(modulusElem,
                                                                  "Exponent",
                                                                  XMLSignature.XMLNS);
            exponent = new DOMCryptoBinary(exponentElem.getFirstChild());
            RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus.getBigNum(),
                                                         exponent.getBigNum());
            return generatePublicKey(rsakf, spec);
        }
    }

    static final class DSA extends DOMKeyValue {
        // DSAKeyValue CryptoBinaries
        private DOMCryptoBinary p, q, g, y, j; //, seed, pgen;
        private KeyFactory dsakf;

        DSA(PublicKey key) throws KeyException {
            super(key);
            DSAPublicKey dkey = (DSAPublicKey) key;
            DSAParams params = dkey.getParams();
            p = new DOMCryptoBinary(params.getP());
            q = new DOMCryptoBinary(params.getQ());
            g = new DOMCryptoBinary(params.getG());
            y = new DOMCryptoBinary(dkey.getY());
        }

        DSA(Element elem) throws MarshalException {
            super(elem);
        }

        void marshalPublicKey(Node parent, Document doc, String dsPrefix, 
                              DOMCryptoContext context)
            throws MarshalException
        {
            Element dsaElem = DOMUtils.createElement(doc, "DSAKeyValue",
                                                     XMLSignature.XMLNS,
                                                     dsPrefix);
            // parameters J, Seed & PgenCounter are not included
            Element pElem = DOMUtils.createElement(doc, "P", XMLSignature.XMLNS,
                                                   dsPrefix);
            Element qElem = DOMUtils.createElement(doc, "Q", XMLSignature.XMLNS,
                                                   dsPrefix);
            Element gElem = DOMUtils.createElement(doc, "G", XMLSignature.XMLNS,
                                                   dsPrefix);
            Element yElem = DOMUtils.createElement(doc, "Y", XMLSignature.XMLNS,
                                                   dsPrefix);
            p.marshal(pElem, dsPrefix, context);
            q.marshal(qElem, dsPrefix, context);
            g.marshal(gElem, dsPrefix, context);
            y.marshal(yElem, dsPrefix, context);
            dsaElem.appendChild(pElem);
            dsaElem.appendChild(qElem);
            dsaElem.appendChild(gElem);
            dsaElem.appendChild(yElem);
            parent.appendChild(dsaElem);
        }

        PublicKey unmarshalKeyValue(Element kvtElem)
            throws MarshalException
        {
            if (dsakf == null) {
                try {
                    dsakf = KeyFactory.getInstance("DSA");
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException
                        ("unable to create DSA KeyFactory: " + e.getMessage());
                }
            }
            Element curElem = DOMUtils.getFirstChildElement(kvtElem);
            if (curElem == null) {
                throw new MarshalException("KeyValue must contain at least one type");
            }
            // check for P and Q
            if (curElem.getLocalName().equals("P") && XMLSignature.XMLNS.equals(curElem.getNamespaceURI())) {
                p = new DOMCryptoBinary(curElem.getFirstChild());
                curElem = DOMUtils.getNextSiblingElement(curElem, "Q", XMLSignature.XMLNS);
                q = new DOMCryptoBinary(curElem.getFirstChild());
                curElem = DOMUtils.getNextSiblingElement(curElem);
            } 
            if (curElem != null 
                && curElem.getLocalName().equals("G") && XMLSignature.XMLNS.equals(curElem.getNamespaceURI())) {
                g = new DOMCryptoBinary(curElem.getFirstChild());
                curElem = DOMUtils.getNextSiblingElement(curElem, "Y");
            }
            if (curElem != null) {
                y = new DOMCryptoBinary(curElem.getFirstChild());
                curElem = DOMUtils.getNextSiblingElement(curElem);
            }
            if (curElem != null && curElem.getLocalName().equals("J")) {
                j = new DOMCryptoBinary(curElem.getFirstChild());
                // curElem = DOMUtils.getNextSiblingElement(curElem);
            }
            /*
            if (curElem != null) {
                seed = new DOMCryptoBinary(curElem.getFirstChild());
                curElem = DOMUtils.getNextSiblingElement(curElem);
                pgen = new DOMCryptoBinary(curElem.getFirstChild());
            }
            */
            //@@@ do we care about j, pgenCounter or seed?
            DSAPublicKeySpec spec = new DSAPublicKeySpec(y.getBigNum(),
                                                         p.getBigNum(),
                                                         q.getBigNum(),
                                                         g.getBigNum());
            return generatePublicKey(dsakf, spec);
        }
    }

    static final class EC extends DOMKeyValue {

        private final static String ver = System.getProperty("java.version");
        private final static boolean atLeast18 = !ver.startsWith("1.5") &&
            !ver.startsWith("1.6") && !ver.startsWith("1.7");
        // ECKeyValue CryptoBinaries
        private byte[] ecPublicKey;
        private KeyFactory eckf;
        private ECParameterSpec ecParams;
        private Method encodePoint, decodePoint;

        EC(PublicKey key) throws KeyException {
            super(key);
            ECPublicKey ecKey = (ECPublicKey)key;
            ECPoint ecPoint = ecKey.getW();
            ecParams = ecKey.getParams();
            try {
                AccessController.doPrivileged(
                    new PrivilegedExceptionAction<Void>() {
                        public Void run() throws
                            ClassNotFoundException, NoSuchMethodException
                        {
                            getMethods();
                            return null;
                        }
                    }
                );
            } catch (PrivilegedActionException pae) {
                throw new KeyException("ECKeyValue not supported",
                                        pae.getException());
            }
            Object[] args = new Object[] { ecPoint, ecParams.getCurve() };
            try {
                ecPublicKey = (byte[])encodePoint.invoke(null, args);
            } catch (IllegalAccessException iae) {
                throw new KeyException(iae);
            } catch (InvocationTargetException ite) {
                throw new KeyException(ite);
            }
        }

        EC(Element dmElem) throws MarshalException {
            super(dmElem);
        }

        void getMethods() throws ClassNotFoundException, NoSuchMethodException {
            String className = atLeast18
                ? "sun.security.util.ECUtil"
                : "sun.security.ec.ECParameters";
            Class c = ClassLoaderUtils.loadClass(className, DOMKeyValue.class);
            Class[] params = new Class<?>[] { ECPoint.class, EllipticCurve.class };
            encodePoint = c.getMethod("encodePoint", params);
            params = new Class[] { ECParameterSpec.class };
            params = new Class[] { byte[].class, EllipticCurve.class };
            decodePoint = c.getMethod("decodePoint", params);
        }

        void marshalPublicKey(Node parent, Document doc, String dsPrefix,
                              DOMCryptoContext context)
            throws MarshalException
        {
            String prefix = DOMUtils.getNSPrefix(context, XMLDSIG_11_XMLNS);
            Element ecKeyValueElem = DOMUtils.createElement(doc, "ECKeyValue",
                                                            XMLDSIG_11_XMLNS,
                                                            prefix);
            Element namedCurveElem = DOMUtils.createElement(doc, "NamedCurve",
                                                            XMLDSIG_11_XMLNS,
                                                            prefix);
            Element publicKeyElem = DOMUtils.createElement(doc, "PublicKey",
                                                           XMLDSIG_11_XMLNS,
                                                           prefix);
            Object[] args = new Object[] { ecParams };
            try {
                String oid = getCurveName(ecParams);
                DOMUtils.setAttribute(namedCurveElem, "URI", "urn:oid:" + oid);
            } catch (GeneralSecurityException gse) {
                throw new MarshalException(gse);
            }
            String qname = (prefix == null || prefix.length() == 0) 
                       ? "xmlns" : "xmlns:" + prefix;
            namedCurveElem.setAttributeNS("http://www.w3.org/2000/xmlns/",
                                          qname, XMLDSIG_11_XMLNS);
            ecKeyValueElem.appendChild(namedCurveElem);
            String encoded = Base64.encode(ecPublicKey);
            publicKeyElem.appendChild
                (DOMUtils.getOwnerDocument(publicKeyElem).createTextNode(encoded));
            ecKeyValueElem.appendChild(publicKeyElem);
            parent.appendChild(ecKeyValueElem);
        }

        private static String getCurveName(ECParameterSpec spec)
            throws GeneralSecurityException
        {
            AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
            ap.init(spec);
            ECGenParameterSpec nameSpec =
                ap.getParameterSpec(ECGenParameterSpec.class);
            if (nameSpec == null) {
                return null;
            }
            return nameSpec.getName();
        }

        PublicKey unmarshalKeyValue(Element kvtElem)
            throws MarshalException
        {
            if (eckf == null) {
                try {
                    eckf = KeyFactory.getInstance("EC");
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException
                        ("unable to create EC KeyFactory: " + e.getMessage());
                }
            }
            try {
                AccessController.doPrivileged(
                    new PrivilegedExceptionAction<Void>() {
                        public Void run() throws
                            ClassNotFoundException, NoSuchMethodException
                        {
                            getMethods();
                            return null;
                        }
                    }
                );
            } catch (PrivilegedActionException pae) {
                throw new MarshalException("ECKeyValue not supported",
                                           pae.getException());
            }
            ECParameterSpec ecParams = null;
            Element curElem = DOMUtils.getFirstChildElement(kvtElem);
            if (curElem == null) {
                throw new MarshalException("KeyValue must contain at least one type");
            }
            
            if (curElem.getLocalName().equals("ECParameters") 
                && XMLDSIG_11_XMLNS.equals(curElem.getNamespaceURI())) {
                throw new UnsupportedOperationException
                    ("ECParameters not supported");
            } else if (curElem.getLocalName().equals("NamedCurve")
                && XMLDSIG_11_XMLNS.equals(curElem.getNamespaceURI())) {
                String uri = DOMUtils.getAttributeValue(curElem, "URI");
                // strip off "urn:oid"
                if (uri.startsWith("urn:oid:")) {
                    String oid = uri.substring(8);
                    try {
                        Object[] args = new Object[] { oid };
                        ecParams = getECParameterSpec(oid);
                    } catch (GeneralSecurityException gse) {
                        throw new MarshalException(gse);
                    }
                } else {
                    throw new MarshalException("Invalid NamedCurve URI");
                }
            } else {
                throw new MarshalException("Invalid ECKeyValue");
            }
            curElem = DOMUtils.getNextSiblingElement(curElem, "PublicKey", XMLDSIG_11_XMLNS);
            ECPoint ecPoint = null;
            try {
                Object[] args = new Object[] { Base64.decode(curElem),
                                               ecParams.getCurve() };
                ecPoint = (ECPoint)decodePoint.invoke(null, args);
            } catch (Base64DecodingException bde) {
                throw new MarshalException("Invalid EC PublicKey", bde);
            } catch (IllegalAccessException iae) {
                throw new MarshalException(iae);
            } catch (InvocationTargetException ite) {
                throw new MarshalException(ite);
            }
/*
                ecPoint = sun.security.ec.ECParameters.decodePoint(
                    Base64.decode(curElem), ecParams.getCurve());
*/
            ECPublicKeySpec spec = new ECPublicKeySpec(ecPoint, ecParams);
            return generatePublicKey(eckf, spec);
        }

        private static ECParameterSpec getECParameterSpec(String name)
            throws GeneralSecurityException
        {
            AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
            ap.init(new ECGenParameterSpec(name));
            return ap.getParameterSpec(ECParameterSpec.class);
        }
    }

    static final class Unknown extends DOMKeyValue {
        private javax.xml.crypto.dom.DOMStructure externalPublicKey;
        Unknown(Element elem) throws MarshalException {
            super(elem);
        }
        PublicKey unmarshalKeyValue(Element kvElem) throws MarshalException {
            externalPublicKey = new javax.xml.crypto.dom.DOMStructure(kvElem);
            return null;
        }
        void marshalPublicKey(Node parent, Document doc, String dsPrefix,
                              DOMCryptoContext context)
            throws MarshalException
        {
            parent.appendChild(externalPublicKey.getNode());
        }
    }
}
