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
package org.apache.xml.security.test.dom.utils;

import java.io.StringReader;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.xml.sax.InputSource;

import com.carrotsearch.junitbenchmarks.AbstractBenchmark;
import com.carrotsearch.junitbenchmarks.BenchmarkOptions;

/**
 * Some benchmark tests for the caching logic in XMLUtils
 */
public class XMLUtilsPerformanceTest extends AbstractBenchmark {

    @BenchmarkOptions(callgc = false, benchmarkRounds = 100000, warmupRounds = 100)
    @Test
    public void testXMLUtils() throws Exception {
        InputSource inputSource = new InputSource(new StringReader("<xml>123</xml>"));
        XMLUtils.read(inputSource, false);
    }

    @BenchmarkOptions(callgc = false, benchmarkRounds = 100000, warmupRounds = 100)
    @Test
    public void testCreateDocumentBuilder() throws Exception {
        DocumentBuilderFactory dfactory = DocumentBuilderFactory.newInstance();
        dfactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, Boolean.TRUE);
        dfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dfactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = dfactory.newDocumentBuilder();

        InputSource inputSource = new InputSource(new StringReader("<xml>123</xml>"));
        documentBuilder.parse(inputSource);
    }

}
