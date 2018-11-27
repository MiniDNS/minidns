/*
 * Copyright 2015-2018 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package org.minidns.dnsserverlookup.android21;

import android.annotation.TargetApi;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.RouteInfo;
import android.os.Build;

import java.util.ArrayList;
import java.util.List;

import org.minidns.DnsClient;
import org.minidns.dnsserverlookup.AbstractDnsServerLookupMechanism;
import org.minidns.dnsserverlookup.AndroidUsingExec;
import org.minidns.dnsserverlookup.IPPortPair;

/**
 * A DNS server lookup mechanism using Android's Link Properties method available on Android API 21 or higher. Use
 * {@link #setup(Context)} to setup this mechanism.
 * <p>
 * Requires the ACCESS_NETWORK_STATE permission.
 * </p>
 */
public class AndroidUsingLinkProperties extends AbstractDnsServerLookupMechanism {

    private final ConnectivityManager connectivityManager;

    /**
     * Setup this DNS server lookup mechanism. You need to invoke this method only once, ideally before you do your
     * first DNS lookup.
     *
     * @param context a Context instance.
     * @return the instance of the newly setup mechanism
     */
    public static AndroidUsingLinkProperties setup(Context context) {
        AndroidUsingLinkProperties androidUsingLinkProperties = new AndroidUsingLinkProperties(context);
        DnsClient.addDnsServerLookupMechanism(androidUsingLinkProperties);
        return androidUsingLinkProperties;
    }

    public AndroidUsingLinkProperties(Context context) {
        super(AndroidUsingLinkProperties.class.getSimpleName(), AndroidUsingExec.PRIORITY - 1);
        connectivityManager = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
    }

    @Override
    public boolean isAvailable() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP;
    }

    @Override
    @TargetApi(21)
    public List<IPPortPair> getDnsServerAddresses() {
        Network[] networks = connectivityManager.getAllNetworks();
        if (networks == null) {
            return null;
        }

        List<String> servers = new ArrayList<>(networks.length * 2);
        for (Network network : networks) {
            LinkProperties linkProperties = connectivityManager.getLinkProperties(network);
            if (linkProperties == null) {
                continue;
            }

            // Prioritize the DNS servers of links which have a default route
            if (hasDefaultRoute(linkProperties)) {
                servers.addAll(0, toListOfStrings(linkProperties.getDnsServers()));
            } else {
                servers.addAll(toListOfStrings(linkProperties.getDnsServers()));
            }
        }

        if (servers.isEmpty()) {
            return null;
        }

        return stringCollectionToListOfIPPortPairs(servers);
    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    private static boolean hasDefaultRoute(LinkProperties linkProperties) {
        for (RouteInfo route : linkProperties.getRoutes()) {
            if (route.isDefaultRoute()) {
                return true;
            }
        }
        return false;
    }

}
