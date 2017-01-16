/*
 * Copyright 2015-2017 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package de.measite.minidns.util;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import de.measite.minidns.record.SRV;

public class SrvUtilTest {

    @Test
    public void sortSRVlowestPrioFirstTest() {
        List<SRV> sortedRecords = SrvUtil.sortSrvRecords(createSRVRecords());
        assertTrue(sortedRecords.get(0).target.ace.equals("0.20.foo.bar"));
    }

    @Test
    public void sortSRVdistributeOverWeights() {
        int weight50 = 0, weight20one = 0, weight20two = 0, weight10 = 0;
        for (int i = 0; i < 1000; i++) {
            List<SRV> sortedRecords = SrvUtil.sortSrvRecords(createSRVRecords());
            String host = sortedRecords.get(1).target.ace;
            if (host.equals("5.20.one.foo.bar")) {
                weight20one++;
            } else if (host.equals("5.20.two.foo.bar")) {
                weight20two++;
            } else if (host.equals("5.10.foo.bar")) {
                weight10++;
            } else if (host.equals("5.50.foo.bar")) {
                weight50++;
            } else {
                fail("Wrong host after SRVRecord sorting");
            }
        }
        assertTrue(weight50 > 400 && weight50 < 600);
        assertTrue(weight20one > 100 && weight20one < 300);
        assertTrue(weight20two > 100 && weight20two < 300);
        assertTrue(weight10 > 0&& weight10 < 200);
    }

    @Test
    public void sortSRVdistributeZeroWeights() {
        int weightZeroOne = 0, weightZeroTwo = 0;
        for (int i = 0; i < 1000; i++) {
            List<SRV> sortedRecords = SrvUtil.sortSrvRecords(createSRVRecords());
            // Remove the first 5 records with a lower priority
            for (int j = 0; j < 5; j++) {
                sortedRecords.remove(0);
            }
            String host = sortedRecords.remove(0).target.ace;
            if (host.equals("10.0.one.foo.bar")) {
                weightZeroOne++;
            } else if (host.endsWith("10.0.two.foo.bar")) {
                weightZeroTwo++;
            } else {
                fail("Wrong host after SRVRecord sorting");
            }
        }
        assertTrue(weightZeroOne > 400 && weightZeroOne < 600);
        assertTrue(weightZeroTwo > 400 && weightZeroTwo < 600);
    }

    private static List<SRV> createSRVRecords() {
        List<SRV> records = new ArrayList<>();

        // We create one record with priority 0 that should also be tried first
        // Then 4 records with priority 5 and different weights (50, 20, 20, 10)
        // Then 2 records with priority 10 and weight 0 which should be treated equal
        // These records are added in a 'random' way to the list
        records.add(new SRV(5, 20, 42, "5.20.one.foo.bar"));  // Priority 5, Weight 20
        records.add(new SRV(10, 0, 42, "10.0.one.foo.bar"));  // Priority 10, Weight 0
        records.add(new SRV(5, 10, 42, "5.10.foo.bar"));      // Priority 5, Weight 10
        records.add(new SRV(10, 0, 42, "10.0.two.foo.bar"));  // Priority 10, Weight 0
        records.add(new SRV(5, 20, 42, "5.20.two.foo.bar"));  // Priority 5, Weight 20
        records.add(new SRV(0, 20, 42, "0.20.foo.bar"));      // Priority 0, Weight 20
        records.add(new SRV(5, 50, 42, "5.50.foo.bar"));      // Priority 5, Weight 50

        return records;
    }
}
