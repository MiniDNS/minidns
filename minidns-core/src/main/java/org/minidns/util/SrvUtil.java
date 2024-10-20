/*
 * Copyright 2015-2024 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package org.minidns.util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.SortedMap;
import java.util.TreeMap;

import org.minidns.dnsname.DnsName;
import org.minidns.record.SRV;

public class SrvUtil {

    /**
     * Sort the given collection of {@link SRV} resource records by their priority and weight.
     * <p>
     * Sorting by priority is easy. Sorting the buckets of SRV records with the same priority by weight requires to choose those records
     * randomly but taking the weight into account.
     * </p>
     *
     * @param srvRecords
     *            a collection of SRV records.
     * @return a sorted list of the given records.
     */
    @SuppressWarnings({"MixedMutabilityReturnType", "JdkObsolete"})
    public static List<SRV> sortSrvRecords(Collection<SRV> srvRecords) {
        // RFC 2782, Usage rules: "If there is precisely one SRV RR, and its Target is "."
        // (the root domain), abort."
        if (srvRecords.size() == 1 && srvRecords.iterator().next().target.equals(DnsName.ROOT)) {
            return Collections.emptyList();
        }

        // Create the priority buckets.
        SortedMap<Integer, List<SRV>> buckets = new TreeMap<>();
        for (SRV srvRecord : srvRecords) {
            Integer priority = srvRecord.priority;
            List<SRV> bucket = buckets.get(priority);
            if (bucket == null) {
                bucket = new LinkedList<>();
                buckets.put(priority, bucket);
            }
            bucket.add(srvRecord);
        }

        List<SRV> sortedSrvRecords = new ArrayList<>(srvRecords.size());

        for (List<SRV> bucket : buckets.values()) {
            // The list of buckets will be sorted by priority, thanks to SortedMap. We now have determine the order of
            // the SRV records with the same priority, i.e., within the same bucket, by their weight. This is done by
            // creating an array 'totals' which reflects the percentage of the SRV RRs weight by the total weight of all
            // SRV RRs in the bucket. For every entry in the bucket, we choose one using a random number and the sum of
            // all weights left in the bucket. We then select RRs position based on the according index of the selected
            // value in the 'total' array. This ensures that its weight is taken into account.
            int bucketSize;
            while ((bucketSize = bucket.size()) > 0) {
                int[] totals = new int[bucketSize];

                int zeroWeight = 1;
                for (SRV srv : bucket) {
                    if (srv.weight > 0) {
                        zeroWeight = 0;
                        break;
                    }
                }

                int bucketWeightSum = 0, count = 0;
                for (SRV srv : bucket) {
                    bucketWeightSum += srv.weight + zeroWeight;
                    totals[count++] = bucketWeightSum;
                }

                int selectedPosition;
                if (bucketWeightSum == 0) {
                    // If total priority is 0, then the sum of all weights in this priority bucket is 0. So we simply
                    // select one of the weights randomly as the other algorithm performed in the else block is unable
                    // to handle this case.
                    selectedPosition = (int) (Math.random() * bucketSize);
                } else {
                    double rnd = Math.random() * bucketWeightSum;
                    selectedPosition = bisect(totals, rnd);
                }

                SRV choosenSrvRecord = bucket.remove(selectedPosition);
                sortedSrvRecords.add(choosenSrvRecord);
            }
        }

        return sortedSrvRecords;
    }

    // TODO This is not yet really bisection just a stupid linear search.
    private static int bisect(int[] array, double value) {
        int pos = 0;
        for (int element : array) {
            if (value < element)
                break;
            pos++;
        }
        return pos;
    }

}
