/*
 * Copyright (c) 2022 Eclipse Foundation and/or its affiliates. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0, which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * This Source Code may also be made available under the following Secondary
 * Licenses when the conditions for such availability set forth in the
 * Eclipse Public License v. 2.0 are satisfied: GNU General Public License,
 * version 2 with the GNU Classpath Exception, which is available at
 * https://www.gnu.org/software/classpath/license.html.
 *
 * SPDX-License-Identifier: EPL-2.0 OR GPL-2.0 WITH Classpath-exception-2.0
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

    public MemoryProfiler(String initLine) {
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
