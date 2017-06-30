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
package de.measite.minidns.source.async;

import java.io.IOException;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.util.concurrent.Future;
import java.util.logging.Level;
import java.util.logging.Logger;

abstract class ChannelSelectedHandler {

    private static final Logger LOGGER = Logger.getLogger(ChannelSelectedHandler.class.getName());

    final Future<?> future;

    ChannelSelectedHandler(Future<?> future) {
        this.future = future;
    }

    void handleChannelSelected(SelectableChannel channel, SelectionKey selectionKey) {
        if (future.isCancelled()) {
            try {
                channel.close();
            } catch (IOException e) {
                LOGGER.log(Level.INFO, "Could not close channel", e);
            }
            return;
        }
        handleChannelSelectedAndNotCancelled(channel, selectionKey);
    }

    protected abstract void handleChannelSelectedAndNotCancelled(SelectableChannel channel, SelectionKey selectionKey);

}
