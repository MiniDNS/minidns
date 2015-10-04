/*
 * Copyright 2015 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package de.measite.minidns.integrationtest;

import de.measite.minidns.dnssec.algorithms.AlgorithmMap;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import static de.measite.minidns.DNSSECConstants.getSignatureAlgorithmName;

public class IntegrationTestHelper {
    private static Set<Class<?>> testClasses;
    private static Logger LOGGER = Logger.getLogger(IntegrationTestHelper.class.getName());
    private static AlgorithmMap referenceAlgorithmMap;

    static {
        testClasses = new HashSet<>();
        testClasses.add(CoreTest.class);
        testClasses.add(DNSSECTest.class);
        testClasses.add(DaneTest.class);
    }

    public static void main(String[] args) throws IllegalAccessException {
        // Disable AlgorithmMap logging
        Logger.getLogger(AlgorithmMap.class.getName()).setLevel(Level.OFF);
        referenceAlgorithmMap = new AlgorithmMap();

        for (final Class<?> aClass : testClasses) {
            for (final Method method : aClass.getDeclaredMethods()) {
                if (method.isAnnotationPresent(IntegrationTest.class)) {
                    invokeTest(method, aClass);
                }
            }
        }
    }

    public static void invokeTest(Method method, Class<?> aClass) {
        Class<?> expected = method.getAnnotation(IntegrationTest.class).expected();
        if (!Exception.class.isAssignableFrom(expected)) expected = null;
        byte sigAlg = method.getAnnotation(IntegrationTest.class).requiredSignatureVerifier();
        if (sigAlg != -1 && referenceAlgorithmMap.getSignatureVerifier(sigAlg) == null) {
            LOGGER.logp(Level.INFO, aClass.getName(), method.getName(), "Test skipped: " + getSignatureAlgorithmName(sigAlg) + " not available on this platform.");
            return;
        }

        try {
            method.invoke(null);

            if (expected != null) {
                LOGGER.logp(Level.WARNING, aClass.getName(), method.getName(), "Test failed: expected exception " + expected + " was not thrown!");
            } else {
                LOGGER.logp(Level.INFO, aClass.getName(), method.getName(), "Test suceeded.");
            }
        } catch (InvocationTargetException e) {
            if (expected != null && expected.isAssignableFrom(e.getTargetException().getClass())) {
                LOGGER.logp(Level.INFO, aClass.getName(), method.getName(), "Test suceeded.");
            } else {
                LOGGER.logp(Level.WARNING, aClass.getName(), method.getName(), "Test failed: unexpected exception was thrown: ", e.getTargetException());
            }
        } catch (IllegalAccessException | NullPointerException e) {
            LOGGER.logp(Level.SEVERE, aClass.getName(), method.getName(), "Test failed: could not invoke test, is it public static?");
        }
    }
}
