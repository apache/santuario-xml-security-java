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

package org.apache.xml.security.test.stax.performance;

import java.io.File;
import java.time.Duration;

import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;

@State(Scope.Benchmark)
public class BenchmarkFiles {

    public Duration warmupDuration;

    // Values must be simple strings.
    // Affects also JMH output which is more simple.
    @Param("")
    private String tmpDir;
    @Param("")
    private String originalFileName;
    @Param("")
    private String processedFileName;

    /**
     * @return input unsigned and unencrypted xml file
     */
    public File getOriginalFile() {
        return originalFileName.isEmpty() ? null : new File(tmpDir, originalFileName);
    }

    /**
     * @return signed or encrypted file
     */
    public File getProcessedFile() {
        return processedFileName.isEmpty() ? null : new File(tmpDir, processedFileName);
    }

    @Override
    public String toString() {
        return "[originalFile=" + originalFileName + "|signedFile=" + processedFileName + "]";
    }
}