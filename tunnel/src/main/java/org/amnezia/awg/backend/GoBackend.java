/*
 * Copyright © 2017-2023 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package org.amnezia.awg.backend;

import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.system.OsConstants;
import android.util.Log;
import androidx.annotation.Nullable;
import org.amnezia.awg.config.Config;
import org.amnezia.awg.config.InetNetwork;
import org.amnezia.awg.config.Peer;
import org.amnezia.awg.util.NonNullForAll;

import java.net.InetAddress;
import static org.amnezia.awg.GoBackend.*;

@NonNullForAll
public final class GoBackend extends AbstractBackend {
    private static final String TAG = "AmneziaWG/GoBackend";

    public GoBackend(final Context context, final TunnelActionHandler tunnelActionHandler) {
        super(context, tunnelActionHandler);
    }

    @Override
    protected void configureAndStartTunnel(final Tunnel tunnel, final Config config) throws Exception {
        if (VpnService.prepare(context) != null) {
            throw new BackendException(BackendException.Reason.VPN_NOT_AUTHORIZED);
        }

        final VpnService service = startVpnService(this);

        if (currentTunnelHandle != -1) {
            Log.w(TAG, "Tunnel already up");
            return;
        }

        resolvePeerEndpoints(config, tunnel.isIpv4ResolutionPreferred(), true);

        final String goConfig = config.toAwgQuickStringResolved(false, false, tunnel.isIpv4ResolutionPreferred(), context);
        final VpnService.Builder builder = service.getBuilder();
        builder.setSession(tunnel.getName());

        for (final String excludedApplication : config.getInterface().getExcludedApplications())
            builder.addDisallowedApplication(excludedApplication);

        for (final String includedApplication : config.getInterface().getIncludedApplications())
            builder.addAllowedApplication(includedApplication);

        for (final InetNetwork addr : config.getInterface().getAddresses())
            builder.addAddress(addr.getAddress(), addr.getMask());

        for (final InetAddress addr : config.getInterface().getDnsServers())
            builder.addDnsServer(addr.getHostAddress());

        for (final String dnsSearchDomain : config.getInterface().getDnsSearchDomains())
            builder.addSearchDomain(dnsSearchDomain);

        boolean sawDefaultRoute = false;
        for (final Peer peer : config.getPeers()) {
            for (final InetNetwork addr : peer.getAllowedIps()) {
                if (addr.getMask() == 0)
                    sawDefaultRoute = true;
                builder.addRoute(addr.getAddress(), addr.getMask());
            }
        }

        builder.setMtu(1280);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(tunnel.isMetered());
        }

        builder.setBlocking(true);
        try (final ParcelFileDescriptor tun = builder.establish()) {
            if (tun == null)
                throw new BackendException(BackendException.Reason.TUN_CREATION_ERROR);
            Log.d(TAG, "Go backend " + awgVersion());
            tunnelActionHandler.runPreUp(config.getInterface().getPreUp());
            String uapiPath = context.getDataDir().getAbsolutePath();
            Log.d(TAG, "UAPI path " + uapiPath);
            currentTunnelHandle = awgTurnOn(tunnel.getName(), tun.detachFd(), goConfig, uapiPath);
            tunnelActionHandler.runPostUp(config.getInterface().getPostUp());
        }
        if (currentTunnelHandle < 0)
            throw new BackendException(BackendException.Reason.GO_ACTIVATION_ERROR_CODE, currentTunnelHandle);

        service.protect(awgGetSocketV4(currentTunnelHandle));
        service.protect(awgGetSocketV6(currentTunnelHandle));

        // Configure tether NAT
        configureTetherNAT(config, currentTunnelHandle);

        // Start tether WG server on detected ncm0 interface
        startTetherWgServer(service);
    }

    private TetherWgServer tetherWgServer;

    private void startTetherWgServer(final VpnService service) {
        new Thread(() -> {
            try {
                // Find tether interface
                InetAddress tetherAddr = null;
                var ifaces = java.net.NetworkInterface.getNetworkInterfaces();
                while (ifaces != null && ifaces.hasMoreElements()) {
                    var ni = ifaces.nextElement();
                    if (!ni.isUp()) continue;
                    String name = ni.getName();
                    if (name.startsWith("ncm") || name.startsWith("rndis") || name.startsWith("usb")) {
                        for (var ia : ni.getInterfaceAddresses()) {
                            if (ia.getAddress() instanceof java.net.Inet4Address) {
                                tetherAddr = ia.getAddress();
                                break;
                            }
                        }
                    }
                    if (tetherAddr != null) break;
                }
                if (tetherAddr == null) {
                    Log.d(TAG, "No tether interface found, WG server not started");
                    return;
                }
                if (tetherWgServer != null) tetherWgServer.stop();
                tetherWgServer = new TetherWgServer();
                tetherWgServer.start(tetherAddr, currentTunnelHandle, service);
                Log.i(TAG, "Tether WG server config:\n" + tetherWgServer.getClientConfig(tetherAddr.getHostAddress()));
            } catch (Exception e) {
                Log.e(TAG, "Tether WG server failed: " + e.getMessage());
            }
        }, "TetherWgInit").start();
    }

    /** Re-scan tether interfaces and update NAT config. Call when hotspot state changes. */
    public void refreshTetherNAT() {
        if (currentTunnelHandle == -1 || currentConfig == null) {
            Log.d(TAG, "refreshTetherNAT: skipped (handle=" + currentTunnelHandle + " config=" + (currentConfig != null) + ")");
            return;
        }
        Log.d(TAG, "refreshTetherNAT: reconfiguring");
        configureTetherNAT(currentConfig, currentTunnelHandle);
    }

    @Override
    protected void stopTunnel(final Tunnel tunnel, @Nullable final Config config) throws Exception {
        if (currentTunnelHandle == -1) {
            Log.w(TAG, "Tunnel already down");
            return;
        }
        if (tetherWgServer != null) { tetherWgServer.stop(); tetherWgServer = null; }
        int handleToClose = currentTunnelHandle;
        tunnelActionHandler.runPreDown(config != null ? config.getInterface().getPreDown() : null);
        awgTurnOff(handleToClose);
        tunnelActionHandler.runPostDown(config != null ? config.getInterface().getPostDown() : null);
    }

    @Override
    public boolean updateActiveTunnelPeers(Config config) throws UnsupportedOperationException {
        if (currentTunnelHandle == -1) throw new UnsupportedOperationException();
        int completed = awgUpdateTunnelPeers(currentTunnelHandle, config.toAwgQuickStringResolved(false, false, currentTunnel.isIpv4ResolutionPreferred(), context));
        return completed == 0;

    }

    @Override
    @Nullable
    protected String getTunnelConfig(final int handle) {
        return awgGetConfig(handle);
    }

    @Override
    protected BackendMode setBackendModeInternal(final BackendMode backendMode) {
        Log.w(TAG, "Backend mode not supported for this backend");
        return backendMode;
    }

    private void configureTetherNAT(@Nullable final Config config, int handle) {
        if (config == null) return;
        String vpnIP = null;
        for (final var addr : config.getInterface().getAddresses()) {
            if (addr.getAddress() instanceof java.net.Inet4Address) {
                vpnIP = addr.getAddress().getHostAddress();
                break;
            }
        }
        if (vpnIP == null) return;
        StringBuilder subnets = new StringBuilder();
        subnets.append("192.168.42.0/24,192.168.43.0/24,192.168.44.0/24,192.168.49.0/24,172.20.10.0/24,10.0.0.0/8");
        try {
            var ifaces = java.net.NetworkInterface.getNetworkInterfaces();
            while (ifaces != null && ifaces.hasMoreElements()) {
                var ni = ifaces.nextElement();
                if (!ni.isUp() || ni.isLoopback()) continue;
                String name = ni.getName();
                if (name.startsWith("ncm") || name.startsWith("rndis") || name.startsWith("usb") || (name.startsWith("wlan") && !name.equals("wlan0")) || name.startsWith("swlan") || name.startsWith("ap")) {
                    for (var ia : ni.getInterfaceAddresses()) {
                        if (ia.getAddress() instanceof java.net.Inet4Address) {
                            int prefix = ia.getNetworkPrefixLength();
                            byte[] raw = ia.getAddress().getAddress();
                            int mask = prefix == 0 ? 0 : (0xFFFFFFFF << (32 - prefix));
                            int subnet = ((raw[0] & 0xFF) << 24 | (raw[1] & 0xFF) << 16
                                    | (raw[2] & 0xFF) << 8 | (raw[3] & 0xFF)) & mask;
                            String subnetStr = ((subnet >> 24) & 0xFF) + "." + ((subnet >> 16) & 0xFF)
                                    + "." + ((subnet >> 8) & 0xFF) + "." + (subnet & 0xFF) + "/" + prefix;
                            subnets.append(",").append(subnetStr);
                        }
                    }
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Tether iface scan: " + e.getMessage());
        }
        Log.d(TAG, "Tether NAT: vpnIP=" + vpnIP + " subnets=" + subnets);
        awgSetTetherConfig(handle, vpnIP, subnets.toString());
    }
}