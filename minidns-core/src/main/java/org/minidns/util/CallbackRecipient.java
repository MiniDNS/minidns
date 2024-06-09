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

/**
 * A recipient of success and exception callbacks.
 *
 * @param <V> the type of the success value.
 * @param <E> the type of the exception.
 */
public interface  CallbackRecipient<V, E> {

    CallbackRecipient<V, E> onSuccess(SuccessCallback<V> successCallback);

    CallbackRecipient<V, E> onError(ExceptionCallback<E> exceptionCallback);

}
