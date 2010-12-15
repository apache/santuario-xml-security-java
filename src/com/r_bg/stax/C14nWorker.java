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

import java.io.OutputStream;

import javax.xml.stream.XMLStreamReader;

import com.r_bg.stax.c14n.C14n;

public class C14nWorker implements StaxWorker {
	DigestResultListener re;
	C14n c14n;
	public C14nWorker(DigestResultListener re, OutputStream os, boolean withComments) {
		c14n=new C14n(new com.r_bg.stax.c14n.AttributeHandleExclusive(),os, withComments);
		this.re=re;
	}

	public StaxWorker read(XMLStreamReader reader) {
		c14n.accept(reader);
		return null;
	}

	public StaxWatcher remove() {
		re.setResult(null);
		return null;
	}
}
