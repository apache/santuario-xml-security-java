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
import java.security.Provider;
import java.util.HashMap;
import java.util.Map;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.Transform;

/**
 * The XMLDSig Stax provider.
 */
public final class StaxProvider extends Provider {

    static final long serialVersionUID = -5049765099299494554L;

    private static final String INFO = "XMLDSig " + 
    "(Stax XMLSignatureFactory; Stax Base64, Inclusive C14N, and Inclusive C14N WithComments TransformService)";

    public StaxProvider() {
	/* We are the Stax provider */
	super("XMLDSig Stax", 0.0, INFO);
	
	final Map map = new HashMap();
        map.put("XMLSignatureFactory.Stax", 
	        "com.r_bg.stax.StaxXMLSignatureFactory");
        map.put((String) "TransformService." + Transform.BASE64, 
	        "com.r_bg.stax.transforms.StaxBase64Transform");
	map.put((String) "TransformService." + Transform.BASE64 +
		" MechanismType", "Stax");
        map.put((String) "TransformService."+ CanonicalizationMethod.INCLUSIVE, 
	        "com.r_bg.stax.transforms.StaxInclusiveC14N");
	map.put((String) "TransformService."+ CanonicalizationMethod.INCLUSIVE +
		" MechanismType", "Stax");
        map.put((String) "TransformService." + 
		CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS, 
	        "com.r_bg.stax.transforms.StaxInclusiveC14NWithComments");
	map.put((String) "TransformService." + 
		CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS +
		" MechanismType", "Stax");
        map.put((String) "TransformService."+ CanonicalizationMethod.EXCLUSIVE, 
	        "com.r_bg.stax.transforms.StaxExclusiveC14N");
	map.put((String) "TransformService."+ CanonicalizationMethod.EXCLUSIVE +
		" MechanismType", "Stax");
        map.put((String) "TransformService." + 
		CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS, 
	        "com.r_bg.stax.transforms.StaxExclusiveC14NWithComments");
	map.put((String) "TransformService." + 
		CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS +
		" MechanismType", "Stax");
	
       	AccessController.doPrivileged(new java.security.PrivilegedAction() {
	    public Object run() {
		putAll(map);
		return null;
	    }
	});
    }
}
