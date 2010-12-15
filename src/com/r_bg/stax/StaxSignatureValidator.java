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
import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.stream.StreamFilter;
import javax.xml.stream.XMLStreamReader;

class IdWatcher implements StaxWatcher {
	String id;
	DigestResultListener re;
	OutputStream os;
	List<Transform> transforms;
	public IdWatcher(String uri, DigestResultListener reader, 
	    List<Transform> transforms, OutputStream os) {
		if (uri.startsWith("xpointer(id(")) {
                    int i1 = uri.indexOf('\'');
                    int i2 = uri.indexOf('\'', i1+1);
                    this.id = uri.substring(i1+1, i2);
                } else {
		    this.id=uri;
		}
		this.re=reader;
		this.transforms=transforms;
		this.os=os;
	}
	public StaxWorker watch(XMLStreamReader reader, StaxSignatureValidator sig) {
		if (id.equals(reader.getAttributeValue(null, "Id"))) {
			if (transforms.isEmpty()) {
			    return new C14nWorker(re, os, false);
			}
			for (Transform t : transforms) {
			    // Only one Transform supported right now
			    return new TransformWorker(t, re, os);
			}
		}
		return null;
	}

	private static class TransformWorker implements StaxWorker {
	    private Transform t;
	    private DigestResultListener re;
	    private OutputStream os;
	    TransformWorker
		(Transform t, DigestResultListener re, OutputStream os) {
		this.t = t;
		this.re = re;
		this.os = os;
	    }
	    public StaxWorker read(XMLStreamReader reader) {
	        try {
	            t.transform(new StaxData(reader), null, os);
	        } catch (TransformException te) {
		    te.printStackTrace();
	        }
		return null;
	    }
	    public StaxWatcher remove() {
		re.setResult(null);
		return null;
	    }
	}
}

public class StaxSignatureValidator implements StreamFilter{
	List<XMLSignatureWorker> signatures=new ArrayList<XMLSignatureWorker>();
	List<StaxWorker> filters=new ArrayList<StaxWorker>();
	List<Integer> filterStart=new ArrayList<Integer>();
	List<StaxWatcher> watchers=new ArrayList<StaxWatcher>();
	int level=0;
	public StaxSignatureValidator(StaxValidateContext context) {
		watchers.add(new SignatureWatcher(context));
	}
	public void addSignature(XMLSignatureWorker s) {
		signatures.add(s);
		
	}
	public void insertWatch(IdWatcher watcher) {
		watchers.add(watcher);
		
	}
	public boolean accept(XMLStreamReader cur) {
		int eventType = cur.getEventType();
		if (eventType==XMLStreamReader.START_ELEMENT) {
			//Start element notify all watcher
			level++;
			for (StaxWatcher watcher : watchers) {
				StaxWorker sf=watcher.watch(cur, this);
				if (sf!=null) {
					//Add a new worker
					filters.add(sf);
					filterStart.add(level);
				}
			}
		}
		List<StaxWorker> added=filters;
		//A worker can add new workers. Iterate while there is more workers to add.
		while (added.size()!=0) {			
			List<StaxWorker> toAdd=new ArrayList<StaxWorker>();
			List<Integer> toAddStart=new ArrayList<Integer>();						
			for (StaxWorker filter: added) {
				StaxWorker sf=filter.read(cur);
				if (sf!=null) {
					toAdd.add(sf);
					toAddStart.add(level);
				}
			}			
			added=toAdd;
			filters.addAll(toAdd);
			filterStart.addAll(toAddStart);
		}
		if (eventType==XMLStreamReader.END_ELEMENT) {
			//an end element remove any worker attached to this element
			do {
				int i=filterStart.lastIndexOf(level);
				if (i!=-1) {
					StaxWatcher watch=filters.remove(i).remove();
					if (watch!=null) {
						watchers.add(watch);
					}
					filterStart.remove(i);
				}
			} while (filterStart.contains(level));
			level--;
		}
		return true;
	}
}
