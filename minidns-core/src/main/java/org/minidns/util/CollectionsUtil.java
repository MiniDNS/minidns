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

import java.util.Iterator;
import java.util.Random;
import java.util.Set;

public class CollectionsUtil {

    public static <T> T getRandomFrom(Set<T> set, Random random) {
        int randomIndex = random.nextInt(set.size());
        Iterator<T> iterator = set.iterator();
        for (int i = 0; i < randomIndex; i++) {
            if (!iterator.hasNext()) break;
            iterator.next();
        }
        return iterator.next();
    }
}
