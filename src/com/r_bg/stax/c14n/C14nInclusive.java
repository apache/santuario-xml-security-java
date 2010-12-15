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
package com.r_bg.stax.c14n;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Iterator;
import java.util.SortedSet;
import java.util.TreeSet;

import javax.xml.stream.XMLStreamReader;
/**
 * TODO: Copy the already defined namespaces sadly stax doesnot give any way to obtain this
 * so we are going to have stack for inclusive.
 * @author raul
 *
 */
public class C14nInclusive implements C14nAttributeHandler {
	public void handleAttributes(XMLStreamReader in,StaxC14nHelper nsD,OutputStream os) throws IOException {
		SortedSet args=new TreeSet(new AttributeCompartor(in));
		SortedSet nss=new TreeSet(new NsCompartor(in));
		int length=in.getNamespaceCount();
		for (int i=0;i<length;i++) {
			if (!nsD.hasBeenRender(in.getNamespacePrefix(i),in.getNamespaceURI(i)))
				nss.add(new Integer(i));
		}
		Iterator it=nss.iterator();
		while (it.hasNext()) {
			int arg=((Integer)it.next()).intValue();
			String prefix=in.getNamespacePrefix(arg);
			if (prefix!="") {
				prefix=" xmlns:"+prefix;
			} else {
				prefix=" xmlns";
			}
			os.write(prefix.getBytes());
			os.write("=\"".getBytes());
			os.write(in.getNamespaceURI(arg).getBytes());
			os.write('\"');
		}
		length=in.getAttributeCount();
		for (int i=0;i<length;i++) {
			args.add(new Integer(i));			
		}
		it=args.iterator();
		for (int i=0;i<length;i++) {
			int arg=((Integer)it.next()).intValue();
			os.write(' ');
			C14n.writeAttribute(in,arg,os);
			os.write("=\"".getBytes());
			os.write(in.getAttributeValue(arg).getBytes());
			os.write('\"');			
		}
		
		return;
	}	

}
