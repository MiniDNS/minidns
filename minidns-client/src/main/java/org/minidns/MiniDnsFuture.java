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
package org.minidns;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.minidns.util.CallbackRecipient;
import org.minidns.util.ExceptionCallback;
import org.minidns.util.MultipleIoException;
import org.minidns.util.SuccessCallback;

public abstract class MiniDnsFuture<V, E extends Exception> implements Future<V>, CallbackRecipient<V, E> {

    private boolean cancelled;

    protected V result;

    protected E exception;

    private SuccessCallback<V> successCallback;

    private ExceptionCallback<E> exceptionCallback;

    @Override
    public synchronized boolean cancel(boolean mayInterruptIfRunning) {
        if (isDone()) {
            return false;
        }

        cancelled = true;

        if (mayInterruptIfRunning) {
            notifyAll();
        }

        return true;
    }

    @Override
    public final synchronized boolean isCancelled() {
        return cancelled;
    }

    @Override
    public final synchronized boolean isDone() {
        return hasResult() || hasException();
    }

    public final synchronized boolean hasResult() {
        return result != null;
    }

    public final synchronized boolean hasException() {
        return exception != null;
    }

    @Override
    public CallbackRecipient<V, E> onSuccess(SuccessCallback<V> successCallback) {
        this.successCallback = successCallback;
        maybeInvokeCallbacks();
        return this;
    }

    @Override
    public CallbackRecipient<V, E> onError(ExceptionCallback<E> exceptionCallback) {
        this.exceptionCallback = exceptionCallback;
        maybeInvokeCallbacks();
        return this;
    }

    private V getOrThrowExecutionException() throws ExecutionException {
        assert result != null || exception != null || cancelled;
        if (result != null) {
            return result;
        }
        if (exception != null) {
            throw new ExecutionException(exception);
        }

        assert cancelled;
        throw new CancellationException();
    }

    @Override
    public final synchronized V get() throws InterruptedException, ExecutionException {
        while (result == null && exception == null && !cancelled) {
            wait();
        }

        return getOrThrowExecutionException();
    }

    public final synchronized V getOrThrow() throws E {
        while (result == null && exception == null && !cancelled) {
            try {
                wait();
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }

        if (exception != null) {
            throw exception;
        }

        if (cancelled) {
            throw new CancellationException();
        }

        assert result != null;
        return result;
    }

    @Override
    public final synchronized V get(long timeout, TimeUnit unit)
                    throws InterruptedException, ExecutionException, TimeoutException {
        final long deadline = System.currentTimeMillis() + unit.toMillis(timeout);
        while (result != null && exception != null && !cancelled) {
            final long waitTimeRemaining = deadline - System.currentTimeMillis();
            if (waitTimeRemaining > 0) {
                wait(waitTimeRemaining);
            }
        }

        if (cancelled) {
            throw new CancellationException();
        }

        if (result == null || exception == null) {
            throw new TimeoutException();
        }

        return getOrThrowExecutionException();
    }

    private static final ExecutorService EXECUTOR_SERVICE;

    static {
        ThreadFactory threadFactory = new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                Thread thread = new Thread(r);
                thread.setDaemon(true);
                thread.setName("MiniDnsFuture Thread");
                return thread;
            }
        };
        BlockingQueue<Runnable> blockingQueue = new ArrayBlockingQueue<>(128);
        RejectedExecutionHandler rejectedExecutionHandler = new RejectedExecutionHandler() {
            @Override
            public void rejectedExecution(Runnable r, ThreadPoolExecutor executor) {
                r.run();
            }
        };
        int cores = Runtime.getRuntime().availableProcessors();
        int maximumPoolSize = cores <= 4 ? 2 : cores;
        ExecutorService executorService = new ThreadPoolExecutor(0, maximumPoolSize, 60L, TimeUnit.SECONDS, blockingQueue, threadFactory,
                rejectedExecutionHandler);

        EXECUTOR_SERVICE = executorService;
    }

    @SuppressWarnings("FutureReturnValueIgnored")
    protected final synchronized void maybeInvokeCallbacks() {
        if (cancelled) {
            return;
        }

        if (result != null && successCallback != null) {
            EXECUTOR_SERVICE.submit(new Runnable() {
                @Override
                public void run() {
                    successCallback.onSuccess(result);
                }
            });
        } else if (exception != null && exceptionCallback != null) {
            EXECUTOR_SERVICE.submit(new Runnable() {
                @Override
                public void run() {
                    exceptionCallback.processException(exception);
                }
            });
        }
    }

    public static class InternalMiniDnsFuture<V, E extends Exception> extends MiniDnsFuture<V, E> {
        public final synchronized void setResult(V result) {
            if (isDone()) {
                return;
            }

            this.result = result;
            this.notifyAll();

            maybeInvokeCallbacks();
        }

        public final synchronized void setException(E exception) {
            if (isDone()) {
                return;
            }

            this.exception = exception;
            this.notifyAll();

            maybeInvokeCallbacks();
        }
    }

    public static <V, E extends Exception> MiniDnsFuture<V, E> from(V result) {
        InternalMiniDnsFuture<V, E> future = new InternalMiniDnsFuture<>();
        future.setResult(result);
        return future;
    }

    public static <V> MiniDnsFuture<V, IOException> anySuccessfulOf(Collection<MiniDnsFuture<V, IOException>> futures) {
        return anySuccessfulOf(futures, exceptions -> MultipleIoException.toIOException(exceptions));
    }

    public interface ExceptionsWrapper<EI extends Exception, EO extends Exception> {
        EO wrap(List<EI> exceptions);
    }

    public static <V, EI extends Exception, EO extends Exception> MiniDnsFuture<V, EO> anySuccessfulOf(
            Collection<MiniDnsFuture<V, EI>> futures,
            ExceptionsWrapper<EI, EO> exceptionsWrapper) {
        InternalMiniDnsFuture<V, EO> returnedFuture = new InternalMiniDnsFuture<>();

        final List<EI> exceptions = Collections.synchronizedList(new ArrayList<>(futures.size()));

        for (MiniDnsFuture<V, EI> future : futures) {
            future.onSuccess(new SuccessCallback<V>() {
                @Override
                public void onSuccess(V result) {
                    // Cancel all futures. Yes, this includes the future which just returned the
                    // result and futures which already failed with an exception, but then cancel
                    // will be a no-op.
                    for (MiniDnsFuture<V, EI> futureToCancel : futures) {
                        futureToCancel.cancel(true);
                    }
                    returnedFuture.setResult(result);
                }
            });
            future.onError(new ExceptionCallback<EI>() {
                @Override
                public void processException(EI exception) {
                    exceptions.add(exception);
                    // Signal the main future about the exceptions, but only if all sub-futures returned an exception.
                    if (exceptions.size() == futures.size()) {
                        EO returnedException = exceptionsWrapper.wrap(exceptions);
                        returnedFuture.setException(returnedException);
                    }
                }
            });
        }

        return returnedFuture;
    }
}
