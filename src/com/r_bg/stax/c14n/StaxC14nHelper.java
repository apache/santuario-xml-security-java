package com.r_bg.stax.c14n;
/*
 * Copyright  2004-2007 The Apache Software Foundation.
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


import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;




/**
 * A stack based Symble Table.
 *<br>For speed reasons all the symbols are introduced in the same map,
 * and at the same time in a list so it can be removed when the frame is pop back.
 * @author Raul Benito
 **/
public class StaxC14nHelper {
	List levels=new ArrayList();
	//boolean needToClone=false;
	HashMap currentRender=new HashMap();
	public StaxC14nHelper() {
		currentRender.put("","");
	}
	public void push() {
		levels.add(currentRender.clone());
	}
	public void pop() {
		currentRender=(HashMap) levels.remove(levels.size()-1);
	}
	public boolean hasBeenRender(String prefix, String uri) {
		String previousRendered=(String) currentRender.get(prefix);
		if ((previousRendered!=null) && (previousRendered.equals(uri))) {								
				return true;			
		}
		currentRender.put(prefix,uri);
		return false;
	}
	
}
