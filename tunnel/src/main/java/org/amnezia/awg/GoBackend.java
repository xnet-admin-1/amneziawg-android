package org.amnezia.awg;

import androidx.annotation.Nullable;

public class GoBackend {
    @Nullable
    public static native String awgGetConfig(int handle);

    public static native int awgGetSocketV4(int handle);

    public static native int awgGetSocketV6(int handle);

    public static native void awgTurnOff(int handle);

    public static native int awgTurnOn(String ifName, int tunFd, String settings, String uapiPath);

    public static native int awgTurnOnRaw(String ifName, int tunFd, String settings);

    public static native int awgUpdateTunnelPeers(int handle, String settings);

    public static native String awgVersion();

    public static native void awgSetTetherConfig(int handle, String vpnIP, String tetherSubnets);

    public static native int awgInjectTetherPacket(int handle, byte[] packet, int size);

    public static native int awgReadTetherPacket(int handle, byte[] buf, int bufSize);
}
