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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.test.JmhUtils;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Timeout;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.xml.sax.InputSource;

import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Some benchmark tests for the caching logic in XMLUtils
 */
@BenchmarkMode(Mode.SampleTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 1)
@Measurement(iterations = 3)
@Threads(20)
@Timeout(time = 1, timeUnit = TimeUnit.MINUTES)
@Fork(1)
@Tag("benchmark")
public class XMLUtilsPerformanceIT {

    @Test
    void runBenchmarks() throws Exception {
        Options options = new OptionsBuilder()
                .include(this.getClass().getName())
                .shouldFailOnError(true)
                .shouldDoGC(true)
                .build();
        JmhUtils.runAndVerify(options, lessThanOrEqualTo(1_000_000d), lessThanOrEqualTo(5_000d));
    }


    @Benchmark
    public void benchmarkXMLUtils() throws Exception {
        InputStream inputStream = new ByteArrayInputStream("<xml>123</xml>".getBytes(StandardCharsets.UTF_8));
        assertNotNull(XMLUtils.read(inputStream, false));
    }


    @Benchmark
    public void benchmarkCreateDocumentBuilder() throws Exception {
        DocumentBuilderFactory dfactory = DocumentBuilderFactory.newInstance();
        dfactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, Boolean.TRUE);
        dfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dfactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = dfactory.newDocumentBuilder();

        InputSource inputSource = new InputSource(new StringReader("<xml>123</xml>"));
        assertNotNull(documentBuilder.parse(inputSource));
    }
}
