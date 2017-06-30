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
package de.measite.minidns;

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

public abstract class MiniDnsFuture<V, E extends Exception> implements Future<V> {

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
    public synchronized final boolean isCancelled() {
        return cancelled;
    }

    @Override
    public synchronized final boolean isDone() {
        return result != null;
    }

    public void onSuccessOrError(SuccessCallback<V> successCallback, ExceptionCallback<E> exceptionCallback) {
        this.successCallback = successCallback;
        this.exceptionCallback = exceptionCallback;

        maybeInvokeCallbacks();
    }

    public void onSuccess(SuccessCallback<V> successCallback) {
        onSuccessOrError(successCallback, null);
    }

    public void onError(ExceptionCallback<E> exceptionCallback) {
        onSuccessOrError(null, exceptionCallback);
    }

    private final V getOrThrowExceptionException() throws ExecutionException {
        assert (result != null || exception != null || cancelled);
        if (result != null) {
            return result;
        }
        if (exception != null) {
            throw new ExecutionException(exception);
        }

        assert (cancelled);
        throw new CancellationException();
    }

    @Override
    public synchronized final V get() throws InterruptedException, ExecutionException {
        while (result == null && exception == null && !cancelled) {
            wait();
        }

        return getOrThrowExceptionException();
    }

    public synchronized final V getOrThrow() throws E {
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
    public synchronized final V get(long timeout, TimeUnit unit)
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

        return getOrThrowExceptionException();
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
            this.result = result;
            this.notifyAll();

            maybeInvokeCallbacks();
        }

        public final synchronized void setException(E exception) {
            this.exception = exception;
            this.notifyAll();

            maybeInvokeCallbacks();
        }
    }

    public interface SuccessCallback<T> {

        public void onSuccess(T result);

    }

    public interface ExceptionCallback<E> {

        public void processException(E exception);

    }

    public static <V, E extends Exception> MiniDnsFuture<V, E> from(V result) {
        InternalMiniDnsFuture<V, E> future = new InternalMiniDnsFuture<>();
        future.setResult(result);
        return future;
    }
}
