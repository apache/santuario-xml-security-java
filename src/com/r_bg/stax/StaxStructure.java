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

import javax.xml.crypto.XMLStructure;
import javax.xml.stream.XMLStreamReader;

public class StaxStructure implements XMLStructure {

    private final XMLStreamReader reader;

    public StaxStructure(XMLStreamReader reader) {
	this.reader = reader;
    }

    public XMLStreamReader getXMLStreamReader() {
	return reader;
    }

    public boolean isFeatureSupported(String feature) {
	return false;
    }
}
