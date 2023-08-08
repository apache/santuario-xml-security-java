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

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.util.Collection;
import java.util.Set;

import org.openjdk.jmh.infra.BenchmarkParams;
import org.openjdk.jmh.infra.IterationParams;
import org.openjdk.jmh.profile.InternalProfiler;
import org.openjdk.jmh.results.IterationResult;
import org.openjdk.jmh.results.ScalarResult;

import static org.openjdk.jmh.results.AggregationPolicy.AVG;

public class MemoryProfiler implements InternalProfiler {

    private final MemoryMXBean mxBean;

    public MemoryProfiler(String initLine) { // NOPMD Implicit arg, despite unused.
        mxBean = ManagementFactory.getMemoryMXBean();
    }

    @Override
    public String getDescription() {
        return "Memory profiling via standard MBeans";
    }

    @Override
    public void beforeIteration(BenchmarkParams benchmarkParams, IterationParams iterationParams) {
        forceCleanup();
    }

    @Override
    public Collection<ScalarResult> afterIteration(BenchmarkParams benchmarkParams,
        IterationParams iterationParams, IterationResult result) {
        forceCleanup();
        return Set.of(
            new ScalarResult("Used Heap", mxBean.getHeapMemoryUsage().getUsed() / 1_000_000d, "MB", AVG),
            new ScalarResult("Used Non-Heap", mxBean.getNonHeapMemoryUsage().getUsed() / 1_000_000d, "MB", AVG)
        );
    }


    private void forceCleanup() {
        System.gc();
        System.runFinalization();
        System.gc();
    }
}
