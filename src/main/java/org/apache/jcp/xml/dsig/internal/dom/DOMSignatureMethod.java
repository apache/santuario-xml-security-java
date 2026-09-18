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
package org.apache.jcp.xml.dsig.internal.dom;

import java.io.IOException;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.HashMap;
import java.util.Map;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLSignContext;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLValidateContext;
import javax.xml.crypto.dsig.spec.SignatureMethodParameterSpec;

import org.apache.jcp.xml.dsig.internal.SignerOutputStream;
import org.apache.xml.security.algorithms.implementations.SignatureECDSA;
import org.apache.xml.security.utils.JavaUtils;
import org.w3c.dom.Element;

/**
 * DOM-based abstract implementation of SignatureMethod.
 *
 */
public abstract class DOMSignatureMethod extends AbstractDOMSignatureMethod {

    private static final String DOM_SIGNATURE_PROVIDER = "org.jcp.xml.dsig.internal.dom.SignatureProvider";

    private static final Logger LOG = System.getLogger(DOMSignatureMethod.class.getName());

    private SignatureMethodParameterSpec params;
    private Signature signature;

    // see RFC 4051 for these algorithm definitions
    static final String RSA_SHA224 =
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224";
    static final String RSA_SHA256 =
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    static final String RSA_SHA384 =
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
    static final String RSA_SHA512 =
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    static final String RSA_RIPEMD160 =
        "http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160";
    static final String ECDSA_SHA1 =
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";
    static final String ECDSA_SHA224 =
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224";
    static final String ECDSA_SHA256 =
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    static final String ECDSA_SHA384 =
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
    static final String ECDSA_SHA512 =
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
    static final String DSA_SHA256 =
        "http://www.w3.org/2009/xmldsig11#dsa-sha256";

    // see RFC 9231 for these algorithm definitions
    static final String ED25519 =
        "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519";
    static final String ED448 =
        "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed448";

    // URIs for ML-DSA (FIPS 204) per draft-eastlake-rfc9231bis-xmlsec-uris-09
    // section 3.3.15 (see SANTUARIO-634).
    static final String ML_DSA_44 =
        "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-44";
    static final String ML_DSA_65 =
        "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-65";
    static final String ML_DSA_87 =
        "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-87";
    static final String ECDSA_SHA3_224 =
        "http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-224";
    static final String ECDSA_SHA3_256 =
        "http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-256";
    static final String ECDSA_SHA3_384 =
        "http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-384";
    static final String ECDSA_SHA3_512 =
        "http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-512";

    // see RFC 6931 for these algorithm definitions
    static final String ECDSA_RIPEMD160 =
        "http://www.w3.org/2007/05/xmldsig-more#ecdsa-ripemd160";
    static final String RSA_SHA1_MGF1 =
        "http://www.w3.org/2007/05/xmldsig-more#sha1-rsa-MGF1";
    static final String RSA_SHA224_MGF1 =
        "http://www.w3.org/2007/05/xmldsig-more#sha224-rsa-MGF1";
    static final String RSA_SHA256_MGF1 =
        "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
    static final String RSA_SHA384_MGF1 =
        "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1";
    static final String RSA_SHA512_MGF1 =
        "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1";
    static final String RSA_RIPEMD160_MGF1 =
        "http://www.w3.org/2007/05/xmldsig-more#ripemd160-rsa-MGF1";
    static final String RSA_SHA3_224_MGF1 =
        "http://www.w3.org/2007/05/xmldsig-more#sha3-224-rsa-MGF1";
    static final String RSA_SHA3_256_MGF1 =
        "http://www.w3.org/2007/05/xmldsig-more#sha3-256-rsa-MGF1";
    static final String RSA_SHA3_384_MGF1 =
        "http://www.w3.org/2007/05/xmldsig-more#sha3-384-rsa-MGF1";
    static final String RSA_SHA3_512_MGF1 =
        "http://www.w3.org/2007/05/xmldsig-more#sha3-512-rsa-MGF1";

    // ==================================================================
    // Algorithm registry.
    //
    // Most SignatureMethod algorithms below differ only by algorithm URI
    // and underlying JCA algorithm name(s); rather than a dedicated
    // subclass per algorithm, a single class per algorithm "shape" (see
    // RSASignatureMethod, RSAPSSSignatureMethod, DSASignatureMethod,
    // ECDSASignatureMethod, EDDSASignatureMethod, MLDSASignatureMethod
    // below) is parameterized with that data and looked up here by URI.
    // A couple of special cases that take caller-supplied parameters
    // (generic RSA-PSS, HMAC output length) don't fit this shape - they
    // stay directly constructed by their callers instead of going
    // through this map; see unmarshal() below and
    // DOMXMLSignatureFactory#newSignatureMethod.
    // ==================================================================

    @FunctionalInterface
    interface ParamsConstructor {
        DOMSignatureMethod newInstance(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException;
    }

    @FunctionalInterface
    interface ElementConstructor {
        DOMSignatureMethod newInstance(Element dmElem) throws MarshalException;
    }

    static final class AlgEntry {
        final ParamsConstructor paramsConstructor;
        final ElementConstructor elementConstructor;

        AlgEntry(ParamsConstructor paramsConstructor, ElementConstructor elementConstructor) {
            this.paramsConstructor = paramsConstructor;
            this.elementConstructor = elementConstructor;
        }
    }

    private static final Map<String, AlgEntry> ALGORITHMS = new HashMap<>();

    private static void register(String algorithmURI, ParamsConstructor paramsConstructor,
                                  ElementConstructor elementConstructor) {
        ALGORITHMS.put(algorithmURI, new AlgEntry(paramsConstructor, elementConstructor));
    }

    private static void registerRSAPSS(String algorithmURI, String jcaFallbackAlgorithm,
                                        PSSParameterSpec pssParameterSpec) {
        register(algorithmURI,
            p -> new RSAPSSSignatureMethod(algorithmURI, jcaFallbackAlgorithm, pssParameterSpec, p),
            e -> new RSAPSSSignatureMethod(algorithmURI, jcaFallbackAlgorithm, pssParameterSpec, e));
    }

    private static void registerECDSA(String algorithmURI, String jcaDigestName) {
        register(algorithmURI,
            p -> new ECDSASignatureMethod(algorithmURI,
                jcaDigestName + "withECDSAinP1363Format", jcaDigestName + "withECDSA", p),
            e -> new ECDSASignatureMethod(algorithmURI,
                jcaDigestName + "withECDSAinP1363Format", jcaDigestName + "withECDSA", e));
    }

    static {
        register(SignatureMethod.RSA_SHA1,
            p -> new RSASignatureMethod(SignatureMethod.RSA_SHA1, "SHA1withRSA", p),
            e -> new RSASignatureMethod(SignatureMethod.RSA_SHA1, "SHA1withRSA", e));
        register(RSA_SHA224,
            p -> new RSASignatureMethod(RSA_SHA224, "SHA224withRSA", p),
            e -> new RSASignatureMethod(RSA_SHA224, "SHA224withRSA", e));
        register(RSA_SHA256,
            p -> new RSASignatureMethod(RSA_SHA256, "SHA256withRSA", p),
            e -> new RSASignatureMethod(RSA_SHA256, "SHA256withRSA", e));
        register(RSA_SHA384,
            p -> new RSASignatureMethod(RSA_SHA384, "SHA384withRSA", p),
            e -> new RSASignatureMethod(RSA_SHA384, "SHA384withRSA", e));
        register(RSA_SHA512,
            p -> new RSASignatureMethod(RSA_SHA512, "SHA512withRSA", p),
            e -> new RSASignatureMethod(RSA_SHA512, "SHA512withRSA", e));
        register(RSA_RIPEMD160,
            p -> new RSASignatureMethod(RSA_RIPEMD160, "RIPEMD160withRSA", p),
            e -> new RSASignatureMethod(RSA_RIPEMD160, "RIPEMD160withRSA", e));
        // Unlike the other *_MGF1 algorithms below, RSA_RIPEMD160_MGF1 has always gone
        // through the plain RSA path rather than RSASSA-PSS parameterization.
        register(RSA_RIPEMD160_MGF1,
            p -> new RSASignatureMethod(RSA_RIPEMD160_MGF1, "RIPEMD160withRSAandMGF1", p),
            e -> new RSASignatureMethod(RSA_RIPEMD160_MGF1, "RIPEMD160withRSAandMGF1", e));

        registerRSAPSS(RSA_SHA1_MGF1, "SHA1withRSAandMGF1",
            new PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1,
                20, PSSParameterSpec.TRAILER_FIELD_BC));
        registerRSAPSS(RSA_SHA224_MGF1, "SHA224withRSAandMGF1",
            new PSSParameterSpec("SHA-224", "MGF1", MGF1ParameterSpec.SHA224,
                28, PSSParameterSpec.TRAILER_FIELD_BC));
        registerRSAPSS(RSA_SHA256_MGF1, "SHA256withRSAandMGF1",
            new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                32, PSSParameterSpec.TRAILER_FIELD_BC));
        registerRSAPSS(RSA_SHA384_MGF1, "SHA384withRSAandMGF1",
            new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384,
                48, PSSParameterSpec.TRAILER_FIELD_BC));
        registerRSAPSS(RSA_SHA512_MGF1, "SHA512withRSAandMGF1",
            new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512,
                64, PSSParameterSpec.TRAILER_FIELD_BC));
        registerRSAPSS(RSA_SHA3_224_MGF1, "SHA3-224withRSAandMGF1",
            new PSSParameterSpec("SHA3-224", "MGF1",
                new MGF1ParameterSpec("SHA3-224"), 28, PSSParameterSpec.TRAILER_FIELD_BC));
        registerRSAPSS(RSA_SHA3_256_MGF1, "SHA3-256withRSAandMGF1",
            new PSSParameterSpec("SHA3-256", "MGF1",
                new MGF1ParameterSpec("SHA3-256"), 32, PSSParameterSpec.TRAILER_FIELD_BC));
        registerRSAPSS(RSA_SHA3_384_MGF1, "SHA3-384withRSAandMGF1",
            new PSSParameterSpec("SHA3-384", "MGF1",
                new MGF1ParameterSpec("SHA3-384"), 48, PSSParameterSpec.TRAILER_FIELD_BC));
        registerRSAPSS(RSA_SHA3_512_MGF1, "SHA3-512withRSAandMGF1",
            new PSSParameterSpec("SHA3-512", "MGF1",
                new MGF1ParameterSpec("SHA3-512"), 64, PSSParameterSpec.TRAILER_FIELD_BC));

        register(SignatureMethod.DSA_SHA1,
            p -> new DSASignatureMethod(SignatureMethod.DSA_SHA1,
                "SHA1withDSAinP1363Format", "SHA1withDSA", p),
            e -> new DSASignatureMethod(SignatureMethod.DSA_SHA1,
                "SHA1withDSAinP1363Format", "SHA1withDSA", e));
        register(DSA_SHA256,
            p -> new DSASignatureMethod(DSA_SHA256,
                "SHA256withDSAinP1363Format", "SHA256withDSA", p),
            e -> new DSASignatureMethod(DSA_SHA256,
                "SHA256withDSAinP1363Format", "SHA256withDSA", e));

        registerECDSA(ECDSA_SHA1, "SHA1");
        registerECDSA(ECDSA_SHA224, "SHA224");
        registerECDSA(ECDSA_SHA256, "SHA256");
        registerECDSA(ECDSA_SHA384, "SHA384");
        registerECDSA(ECDSA_SHA512, "SHA512");
        registerECDSA(ECDSA_SHA3_224, "SHA3-224");
        registerECDSA(ECDSA_SHA3_256, "SHA3-256");
        registerECDSA(ECDSA_SHA3_384, "SHA3-384");
        registerECDSA(ECDSA_SHA3_512, "SHA3-512");
        // "RIPEMD160withECDSAinP1363Format" - is this real? kept as-is from the
        // pre-existing per-algorithm implementation.
        registerECDSA(ECDSA_RIPEMD160, "RIPEMD160");

        register(ED25519,
            p -> new EDDSASignatureMethod(ED25519, "Ed25519", p),
            e -> new EDDSASignatureMethod(ED25519, "Ed25519", e));
        register(ED448,
            p -> new EDDSASignatureMethod(ED448, "Ed448", p),
            e -> new EDDSASignatureMethod(ED448, "Ed448", e));

        register(ML_DSA_44,
            p -> new MLDSASignatureMethod(ML_DSA_44, "ML-DSA-44", p),
            e -> new MLDSASignatureMethod(ML_DSA_44, "ML-DSA-44", e));
        register(ML_DSA_65,
            p -> new MLDSASignatureMethod(ML_DSA_65, "ML-DSA-65", p),
            e -> new MLDSASignatureMethod(ML_DSA_65, "ML-DSA-65", e));
        register(ML_DSA_87,
            p -> new MLDSASignatureMethod(ML_DSA_87, "ML-DSA-87", p),
            e -> new MLDSASignatureMethod(ML_DSA_87, "ML-DSA-87", e));
    }

    /**
     * Looks up the algorithm registered for {@code algorithmURI}, if any. Used by
     * both {@link #unmarshal unmarshal} (inbound, from an Element) and
     * {@code DOMXMLSignatureFactory#newSignatureMethod} (outbound, from caller
     * params) so the two entry points share one algorithm table instead of two
     * separately maintained dispatch chains.
     */
    static AlgEntry lookup(String algorithmURI) {
        return ALGORITHMS.get(algorithmURI);
    }

    /**
     * Creates a <code>DOMSignatureMethod</code>.
     *
     * @param params the algorithm-specific params (may be <code>null</code>)
     * @throws InvalidAlgorithmParameterException if the parameters are not
     *    appropriate for this signature method
     */
    DOMSignatureMethod(AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        if (params != null &&
            !(params instanceof SignatureMethodParameterSpec)) {
            throw new InvalidAlgorithmParameterException
                ("params must be of type SignatureMethodParameterSpec");
        }
        checkParams((SignatureMethodParameterSpec)params);
        this.params = (SignatureMethodParameterSpec)params;
    }

    /**
     * Creates a <code>DOMSignatureMethod</code> from an element. This ctor
     * invokes the {@link #unmarshalParams unmarshalParams} method to
     * unmarshal any algorithm-specific input parameters.
     *
     * @param smElem a SignatureMethod element
     */
    DOMSignatureMethod(Element smElem) throws MarshalException {
        Element paramsElem = DOMUtils.getFirstChildElement(smElem);
        if (paramsElem != null) {
            params = unmarshalParams(paramsElem);
        }
        try {
            checkParams(params);
        } catch (InvalidAlgorithmParameterException iape) {
            throw new MarshalException(iape);
        }
    }

    /**
     * Returns the signature bytes with any additional formatting
     * necessary for the signature algorithm used. For RSA signatures,
     * no changes are required, and this method should simply return
     * back {@code sig}. For DSA and ECDSA, this method should return the
     * signature in the IEEE P1363 format, the concatenation of r and s.
     *
     * @param key the key used to sign
     * @param sig the signature returned by {@code Signature.sign()}
     * @return the formatted signature
     * @throws IOException
     */
    abstract byte[] postSignFormat(Key key, byte[] sig) throws IOException;

    /**
     * Returns the signature bytes with any conversions that are necessary
     * before the signature can be verified. For RSA signatures,
     * no changes are required, and this method should simply
     * return back {@code sig}. For DSA and ECDSA, this method should
     * return the signature in the DER-encoded ASN.1 format.
     *
     * @param key the key used to sign
     * @param sig the signature
     * @return the formatted signature
     * @throws IOException
     */
    abstract byte[] preVerifyFormat(Key key, byte[] sig) throws IOException;

    static SignatureMethod unmarshal(Element smElem) throws MarshalException {
        String alg = DOMUtils.getAttributeValue(smElem, "Algorithm");
        if (alg.equals(DOMRSAPSSSignatureMethod.RSA_PSS)) {
            return new DOMRSAPSSSignatureMethod.RSAPSS(smElem);
        } else if (alg.equals(SignatureMethod.HMAC_SHA1)) {
            return new DOMHMACSignatureMethod.SHA1(smElem);
        } else if (alg.equals(DOMHMACSignatureMethod.HMAC_SHA224)) {
            return new DOMHMACSignatureMethod.SHA224(smElem);
        } else if (alg.equals(DOMHMACSignatureMethod.HMAC_SHA256)) {
            return new DOMHMACSignatureMethod.SHA256(smElem);
        } else if (alg.equals(DOMHMACSignatureMethod.HMAC_SHA384)) {
            return new DOMHMACSignatureMethod.SHA384(smElem);
        } else if (alg.equals(DOMHMACSignatureMethod.HMAC_SHA512)) {
            return new DOMHMACSignatureMethod.SHA512(smElem);
        } else if (alg.equals(DOMHMACSignatureMethod.HMAC_RIPEMD160)) {
            return new DOMHMACSignatureMethod.RIPEMD160(smElem);
        }
        AlgEntry entry = ALGORITHMS.get(alg);
        if (entry == null) {
            throw new MarshalException
                ("unsupported SignatureMethod algorithm: " + alg);
        }
        return entry.elementConstructor.newInstance(smElem);
    }

    @Override
    public final AlgorithmParameterSpec getParameterSpec() {
        return params;
    }

    /**
     * Returns an instance of Signature from the specified Provider.
     * The algorithm is specified by the {@code getJCAAlgorithm()} method.
     *
     * @param p the Provider to use
     * @return an instance of Signature implementing the algorithm
     *    specified by {@code getJCAAlgorithm()}
     * @throws NoSuchAlgorithmException if the Provider does not support the
     *    signature algorithm
     */
    Signature getSignature(Provider p)
            throws NoSuchAlgorithmException {
        return (p == null)
            ? Signature.getInstance(getJCAAlgorithm())
            : Signature.getInstance(getJCAAlgorithm(), p);
    }

    @Override
    boolean verify(Key key, SignedInfo si, byte[] sig,
                   XMLValidateContext context)
        throws InvalidKeyException, SignatureException, XMLSignatureException
    {
        if (key == null || si == null || sig == null) {
            throw new NullPointerException();
        }

        if (!(key instanceof PublicKey)) {
            throw new InvalidKeyException("key must be PublicKey");
        }
        if (signature == null) {
            Provider p = (Provider)context.getProperty(DOM_SIGNATURE_PROVIDER);
            try {
                signature = getSignature(p);
            } catch (NoSuchAlgorithmException nsae) {
                throw new XMLSignatureException(nsae);
            }
        }
        signature.initVerify((PublicKey)key);
        LOG.log(Level.DEBUG, "Signature provider: {0}", signature.getProvider());
        LOG.log(Level.DEBUG, "Verifying with key: {0}", key);
        LOG.log(Level.DEBUG, "JCA Algorithm: {0}", getJCAAlgorithm());
        LOG.log(Level.DEBUG, "Signature Bytes length: {0}", sig.length);

        byte[] s;
        try (SignerOutputStream outputStream = new SignerOutputStream(signature)) {
            ((DOMSignedInfo)si).canonicalize(context, outputStream);
            // Do any necessary format conversions
            s = preVerifyFormat(key, sig);
        } catch (IOException ioe) {
            throw new XMLSignatureException(ioe);
        }
        return signature.verify(s);
    }

    @Override
    byte[] sign(Key key, SignedInfo si, XMLSignContext context)
        throws InvalidKeyException, XMLSignatureException
    {
        if (key == null || si == null) {
            throw new NullPointerException();
        }

        if (!(key instanceof PrivateKey)) {
            throw new InvalidKeyException("key must be PrivateKey");
        }
        if (signature == null) {
            Provider p = (Provider)context.getProperty(DOM_SIGNATURE_PROVIDER);
            try {
                signature = getSignature(p);
            } catch (NoSuchAlgorithmException nsae) {
                throw new XMLSignatureException(nsae);
            }
        }
        signature.initSign((PrivateKey)key);
        LOG.log(Level.DEBUG, "Signature provider: {0}", signature.getProvider());
        LOG.log(Level.DEBUG, "JCA Algorithm: {0}", getJCAAlgorithm());

        try (SignerOutputStream outputStream = new SignerOutputStream(signature)) {
            ((DOMSignedInfo)si).canonicalize(context, outputStream);
            // Return signature with any necessary format conversions
            return postSignFormat(key, signature.sign());
        } catch (SignatureException | IOException ex){
            throw new XMLSignatureException(ex);
        }
    }

    abstract static class AbstractRSASignatureMethod
            extends DOMSignatureMethod {

        AbstractRSASignatureMethod(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }

        AbstractRSASignatureMethod(Element dmElem) throws MarshalException {
            super(dmElem);
        }

        /**
         * Returns {@code sig}. No extra formatting is necessary for RSA.
         */
        @Override
        byte[] postSignFormat(Key key, byte[] sig) {
            return sig;
        }

        /**
         * Returns {@code sig}. No extra formatting is necessary for RSA.
         */
        @Override
        byte[] preVerifyFormat(Key key, byte[] sig) {
            return sig;
        }

        @Override
        Type getAlgorithmType() {
            return Type.RSA;
        }
    }

    abstract static class AbstractRSAPSSSignatureMethod
            extends AbstractRSASignatureMethod {

        AbstractRSAPSSSignatureMethod(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }

        AbstractRSAPSSSignatureMethod(Element dmElem) throws MarshalException {
            super(dmElem);
        }

        public abstract PSSParameterSpec getPSSParameterSpec();

        @Override
        Signature getSignature(Provider p)
                throws NoSuchAlgorithmException {
            try {
                Signature s = (p == null)
                        ? Signature.getInstance("RSASSA-PSS")
                        : Signature.getInstance("RSASSA-PSS", p);
                try {
                    s.setParameter(getPSSParameterSpec());
                } catch (InvalidAlgorithmParameterException e) {
                    throw new NoSuchAlgorithmException("Should not happen", e);
                }
                return s;
            } catch (NoSuchAlgorithmException nsae) {
                return super.getSignature(p);
            }
        }
    }
    /**
     * Abstract class to support signature algorithms that sign and verify
     * signatures in the IEEE P1363 format. The P1363 format is the
     * concatenation of r and s in DSA and ECDSA signatures, and thus, only
     * DSA and ECDSA signature methods should extend this class. Subclasses
     * must supply a fallback algorithm to be used when the provider does
     * not offer signature algorithms that use the P1363 format.
     */
    abstract static class AbstractP1363FormatSignatureMethod
            extends DOMSignatureMethod {

        /* Set to true when the fallback algorithm is used */
        boolean asn1;

        AbstractP1363FormatSignatureMethod(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }

        AbstractP1363FormatSignatureMethod(Element dmElem)
                throws MarshalException {
            super(dmElem);
        }

        /**
         * Return the fallback algorithm to be used when the provider does not
         * support signatures in the IEEE P1363 format. This algorithm should
         * return signatures in the DER-encoded ASN.1 format.
         */
        abstract String getJCAFallbackAlgorithm();

        /*
         * Try to return an instance of Signature implementing signatures
         * in the IEEE P1363 format. If the provider doesn't support the
         * P1363 format, return an instance of Signature implementing
         * signatures in the DER-encoded ASN.1 format.
         */
        @Override
        Signature getSignature(Provider p)
                throws NoSuchAlgorithmException {
            try {
                return (p == null)
                    ? Signature.getInstance(getJCAAlgorithm())
                    : Signature.getInstance(getJCAAlgorithm(), p);
            } catch (NoSuchAlgorithmException nsae) {
                Signature s = (p == null)
                    ? Signature.getInstance(getJCAFallbackAlgorithm())
                    : Signature.getInstance(getJCAFallbackAlgorithm(), p);
                asn1 = true;
                return s;
            }
        }
    }

    abstract static class AbstractDSASignatureMethod
        extends AbstractP1363FormatSignatureMethod {

        AbstractDSASignatureMethod(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }

        AbstractDSASignatureMethod(Element dmElem) throws MarshalException {
            super(dmElem);
        }

        @Override
        byte[] postSignFormat(Key key, byte[] sig) throws IOException {
            // If signature is in ASN.1 (i.e., if the fallback algorithm
            // was used), convert the signature to the P1363 format
            if (asn1) {
                int size = ((DSAKey) key).getParams().getQ().bitLength();
                return JavaUtils.convertDsaASN1toXMLDSIG(sig, size / 8);
            } else {
                return sig;
            }
        }

        @Override
        byte[] preVerifyFormat(Key key, byte[] sig) throws IOException {
            // If signature needs to be in ASN.1 (i.e., if the fallback
            // algorithm will be used to verify the sig), convert the signature
            // to the ASN.1 format
            if (asn1) {
                int size = ((DSAKey) key).getParams().getQ().bitLength();
                return JavaUtils.convertDsaXMLDSIGtoASN1(sig, size / 8);
            } else {
                return sig;
            }
        }

        @Override
        Type getAlgorithmType() {
            return Type.DSA;
        }
    }

    abstract static class AbstractECDSASignatureMethod
        extends AbstractP1363FormatSignatureMethod {

        AbstractECDSASignatureMethod(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }

        AbstractECDSASignatureMethod(Element dmElem) throws MarshalException {
            super(dmElem);
        }

        @Override
        byte[] postSignFormat(Key key, byte[] sig) throws IOException {
            // If signature is in ASN.1 (i.e., if the fallback algorithm
            // was used), convert the signature to the P1363 format
            if (asn1) {
                int rawLen = -1;
                if (key instanceof ECPrivateKey) {
                    ECPrivateKey ecKey = (ECPrivateKey)key;
                    rawLen = (ecKey.getParams().getCurve().getField().getFieldSize() + 7) / 8;
                }
                return SignatureECDSA.convertASN1toXMLDSIG(sig, rawLen);
            } else {
                return sig;
            }
        }

        @Override
        byte[] preVerifyFormat(Key key, byte[] sig) throws IOException {
            // If signature needs to be in ASN.1 (i.e., if the fallback
            // algorithm will be used to verify the sig), convert the signature
            // to the ASN.1 format
            if (asn1) {
                return SignatureECDSA.convertXMLDSIGtoASN1(sig);
            } else {
                return sig;
            }
        }

        @Override
        Type getAlgorithmType() {
            return Type.ECDSA;
        }
    }

    abstract static class AbstractEDDSASignatureMethod
            extends DOMSignatureMethod {


        AbstractEDDSASignatureMethod(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }

        AbstractEDDSASignatureMethod(Element dmElem) throws MarshalException {
            super(dmElem);
        }

        /**
         * Returns {@code sig}. No extra formatting is necessary for EDDSA
         * See the RFC8032
         */
        @Override
        byte[] postSignFormat(Key key, byte[] sig) {
            return sig;
        }

        /**
         * Returns {@code sig}. No extra formatting is necessary for EDDSA
         * See the RFC8032
         */
        @Override
        byte[] preVerifyFormat(Key key, byte[] sig) {
            return sig;
        }

        @Override
        Type getAlgorithmType() {
            return Type.EDDSA;
        }
    }

    abstract static class AbstractMLDSASignatureMethod extends DOMSignatureMethod {

        AbstractMLDSASignatureMethod(AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
        }

        AbstractMLDSASignatureMethod(Element dmElem) throws MarshalException {
            super(dmElem);
        }

        /** ML-DSA signatures are raw bytes; no reformatting needed. */
        @Override
        byte[] postSignFormat(Key key, byte[] sig) {
            return sig;
        }

        /** ML-DSA signatures are raw bytes; no reformatting needed. */
        @Override
        byte[] preVerifyFormat(Key key, byte[] sig) {
            return sig;
        }

        @Override
        Type getAlgorithmType() {
            return Type.MLDSA;
        }
    }

    /**
     * A plain RSA signature algorithm (no P1363 conversion, no PSS parameters),
     * e.g. SHA256withRSA. Replaces what used to be one dedicated subclass per
     * algorithm URI; see the {@code register(...)} calls above for the concrete
     * (URI, JCA algorithm name) pairs.
     */
    static final class RSASignatureMethod extends AbstractRSASignatureMethod {
        private final String algorithmURI;
        private final String jcaAlgorithm;

        RSASignatureMethod(String algorithmURI, String jcaAlgorithm,
                            AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
            this.algorithmURI = algorithmURI;
            this.jcaAlgorithm = jcaAlgorithm;
        }

        RSASignatureMethod(String algorithmURI, String jcaAlgorithm, Element dmElem)
                throws MarshalException {
            super(dmElem);
            this.algorithmURI = algorithmURI;
            this.jcaAlgorithm = jcaAlgorithm;
        }

        @Override
        public String getAlgorithm() {
            return algorithmURI;
        }

        @Override
        String getJCAAlgorithm() {
            return jcaAlgorithm;
        }
    }

    /**
     * An RSASSA-PSS signature algorithm with a fixed (algorithm-specific)
     * {@link PSSParameterSpec}, e.g. SHA256withRSAandMGF1. Replaces what used
     * to be one dedicated subclass per digest; see the {@code registerRSAPSS(...)}
     * calls above. Distinct from the generic {@code RSA-PSS} algorithm
     * (see {@link DOMRSAPSSSignatureMethod}), whose PSS parameters are supplied
     * by the caller rather than fixed per URI - that one is still constructed
     * directly, not through this registry.
     */
    static final class RSAPSSSignatureMethod extends AbstractRSAPSSSignatureMethod {
        private final String algorithmURI;
        private final String jcaFallbackAlgorithm;
        private final PSSParameterSpec pssParameterSpec;

        RSAPSSSignatureMethod(String algorithmURI, String jcaFallbackAlgorithm,
                              PSSParameterSpec pssParameterSpec,
                              AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
            this.algorithmURI = algorithmURI;
            this.jcaFallbackAlgorithm = jcaFallbackAlgorithm;
            this.pssParameterSpec = pssParameterSpec;
        }

        RSAPSSSignatureMethod(String algorithmURI, String jcaFallbackAlgorithm,
                              PSSParameterSpec pssParameterSpec, Element dmElem)
                throws MarshalException {
            super(dmElem);
            this.algorithmURI = algorithmURI;
            this.jcaFallbackAlgorithm = jcaFallbackAlgorithm;
            this.pssParameterSpec = pssParameterSpec;
        }

        @Override
        public String getAlgorithm() {
            return algorithmURI;
        }

        @Override
        public PSSParameterSpec getPSSParameterSpec() {
            return pssParameterSpec;
        }

        /**
         * The provider-specific fallback name used when the generic
         * {@code RSASSA-PSS} algorithm isn't available (see
         * {@link AbstractRSAPSSSignatureMethod#getSignature}).
         */
        @Override
        String getJCAAlgorithm() {
            return jcaFallbackAlgorithm;
        }
    }

    /**
     * A DSA signature algorithm using the IEEE P1363 format, with an ASN.1
     * fallback, e.g. SHA256withDSA. Replaces what used to be one dedicated
     * subclass per digest; see the {@code register(...)} calls above.
     */
    static final class DSASignatureMethod extends AbstractDSASignatureMethod {
        private final String algorithmURI;
        private final String jcaAlgorithm;
        private final String jcaFallbackAlgorithm;

        DSASignatureMethod(String algorithmURI, String jcaAlgorithm,
                            String jcaFallbackAlgorithm, AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
            this.algorithmURI = algorithmURI;
            this.jcaAlgorithm = jcaAlgorithm;
            this.jcaFallbackAlgorithm = jcaFallbackAlgorithm;
        }

        DSASignatureMethod(String algorithmURI, String jcaAlgorithm,
                            String jcaFallbackAlgorithm, Element dmElem)
                throws MarshalException {
            super(dmElem);
            this.algorithmURI = algorithmURI;
            this.jcaAlgorithm = jcaAlgorithm;
            this.jcaFallbackAlgorithm = jcaFallbackAlgorithm;
        }

        @Override
        public String getAlgorithm() {
            return algorithmURI;
        }

        @Override
        String getJCAAlgorithm() {
            return jcaAlgorithm;
        }

        @Override
        String getJCAFallbackAlgorithm() {
            return jcaFallbackAlgorithm;
        }
    }

    /**
     * An ECDSA signature algorithm using the IEEE P1363 format, with an ASN.1
     * fallback, e.g. SHA256withECDSA. Replaces what used to be one dedicated
     * subclass per digest; see the {@code registerECDSA(...)} calls above.
     */
    static final class ECDSASignatureMethod extends AbstractECDSASignatureMethod {
        private final String algorithmURI;
        private final String jcaAlgorithm;
        private final String jcaFallbackAlgorithm;

        ECDSASignatureMethod(String algorithmURI, String jcaAlgorithm,
                              String jcaFallbackAlgorithm, AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
            this.algorithmURI = algorithmURI;
            this.jcaAlgorithm = jcaAlgorithm;
            this.jcaFallbackAlgorithm = jcaFallbackAlgorithm;
        }

        ECDSASignatureMethod(String algorithmURI, String jcaAlgorithm,
                              String jcaFallbackAlgorithm, Element dmElem)
                throws MarshalException {
            super(dmElem);
            this.algorithmURI = algorithmURI;
            this.jcaAlgorithm = jcaAlgorithm;
            this.jcaFallbackAlgorithm = jcaFallbackAlgorithm;
        }

        @Override
        public String getAlgorithm() {
            return algorithmURI;
        }

        @Override
        String getJCAAlgorithm() {
            return jcaAlgorithm;
        }

        @Override
        String getJCAFallbackAlgorithm() {
            return jcaFallbackAlgorithm;
        }
    }

    /**
     * An EdDSA signature algorithm, e.g. Ed25519. Replaces what used to be one
     * dedicated subclass per curve; see the {@code register(...)} calls above.
     */
    static final class EDDSASignatureMethod extends AbstractEDDSASignatureMethod {
        private final String algorithmURI;
        private final String jcaAlgorithm;

        EDDSASignatureMethod(String algorithmURI, String jcaAlgorithm,
                              AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
            this.algorithmURI = algorithmURI;
            this.jcaAlgorithm = jcaAlgorithm;
        }

        EDDSASignatureMethod(String algorithmURI, String jcaAlgorithm, Element dmElem)
                throws MarshalException {
            super(dmElem);
            this.algorithmURI = algorithmURI;
            this.jcaAlgorithm = jcaAlgorithm;
        }

        @Override
        public String getAlgorithm() {
            return algorithmURI;
        }

        @Override
        String getJCAAlgorithm() {
            return jcaAlgorithm;
        }
    }

    /**
     * An ML-DSA (FIPS 204) signature algorithm, e.g. ML-DSA-65. Replaces what
     * used to be one dedicated subclass per parameter set; see the
     * {@code register(...)} calls above.
     */
    static final class MLDSASignatureMethod extends AbstractMLDSASignatureMethod {
        private final String algorithmURI;
        private final String jcaAlgorithm;

        MLDSASignatureMethod(String algorithmURI, String jcaAlgorithm,
                              AlgorithmParameterSpec params)
                throws InvalidAlgorithmParameterException {
            super(params);
            this.algorithmURI = algorithmURI;
            this.jcaAlgorithm = jcaAlgorithm;
        }

        MLDSASignatureMethod(String algorithmURI, String jcaAlgorithm, Element dmElem)
                throws MarshalException {
            super(dmElem);
            this.algorithmURI = algorithmURI;
            this.jcaAlgorithm = jcaAlgorithm;
        }

        @Override
        public String getAlgorithm() {
            return algorithmURI;
        }

        @Override
        String getJCAAlgorithm() {
            return jcaAlgorithm;
        }
    }
}
