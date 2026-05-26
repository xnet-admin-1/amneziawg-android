package org.amnezia.awg.backend;

import android.net.VpnService;
import android.util.Log;

import org.amnezia.awg.GoBackend;
import org.amnezia.awg.crypto.Key;
import org.amnezia.awg.crypto.KeyPair;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Base64;

/**
 * WireGuard server on the tether interface (ncm0).
 * Laptop connects as WG client. Decrypted packets are injected into the main
 * WG tunnel via awgInjectTetherPacket. Responses are read via awgReadTetherPacket
 * and sent back encrypted to the laptop.
 *
 * This uses a SECOND wireguard-go device (server mode) with a socketpair TUN.
 * Decrypted packets from the server device are forwarded to the main tunnel.
 */
public class TetherWgServer {
    private static final String TAG = "TetherWgServer";
    private static final int LISTEN_PORT = 51820;
    private static final String SERVER_TUNNEL_IP = "10.99.0.1";
    private static final String CLIENT_TUNNEL_IP = "10.99.0.2";

    private int serverHandle = -1;
    private int mainTunnelHandle = -1;
    private volatile boolean running;
    private Thread injectThread;
    private Thread responseThread;

    private KeyPair serverKeyPair;
    private KeyPair clientKeyPair;

    public void start(InetAddress bindAddr, int mainHandle, VpnService vpn) {
        this.mainTunnelHandle = mainHandle;
        generateKeys();

        try {
            // Create socketpair for the server's virtual TUN
            int[] fds = createSocketPair();
            if (fds == null) {
                Log.e(TAG, "Failed to create socketpair");
                return;
            }
            int serverTunFd = fds[0]; // Go reads/writes this
            int javaTunFd = fds[1];   // We read/write this

            // Build server IPC config
            String config = buildServerIpcConfig();
            Log.d(TAG, "Starting WG server on " + bindAddr.getHostAddress() + ":" + LISTEN_PORT);

            serverHandle = GoBackend.awgTurnOn("wg-tether", serverTunFd, config, "/dev/null");
            if (serverHandle < 0) {
                Log.e(TAG, "wgTurnOn failed: " + serverHandle);
                return;
            }

            // Protect server's UDP socket
            int sock4 = GoBackend.awgGetSocketV4(serverHandle);
            if (sock4 >= 0 && vpn != null) {
                vpn.protect(sock4);
            }

            running = true;

            // Thread: read decrypted packets from server TUN → inject into main tunnel
            final android.os.ParcelFileDescriptor javaPfd = android.os.ParcelFileDescriptor.adoptFd(javaTunFd);
            injectThread = new Thread(() -> {
                byte[] buf = new byte[1500];
                try (var in = new java.io.FileInputStream(javaPfd.getFileDescriptor())) {
                    while (running) {
                        int n = in.read(buf);
                        if (n > 0) {
                            GoBackend.awgInjectTetherPacket(mainTunnelHandle, buf, n);
                        }
                    }
                } catch (Exception e) {
                    if (running) Log.w(TAG, "inject: " + e.getMessage());
                }
            }, "WG-tether-inject");
            injectThread.start();

            // Thread: read responses from main tunnel → write to server TUN
            responseThread = new Thread(() -> {
                byte[] buf = new byte[1500];
                try (var out = new java.io.FileOutputStream(javaPfd.getFileDescriptor())) {
                    while (running) {
                        int n = GoBackend.awgReadTetherPacket(mainTunnelHandle, buf, buf.length);
                        if (n > 0) {
                            out.write(buf, 0, n);
                        } else {
                            Thread.sleep(1);
                        }
                    }
                } catch (Exception e) {
                    if (running) Log.w(TAG, "response: " + e.getMessage());
                }
            }, "WG-tether-response");
            responseThread.start();

            Log.i(TAG, "WG tether server started, handle=" + serverHandle);
        } catch (Exception e) {
            Log.e(TAG, "start failed", e);
        }
    }

    public void stop() {
        running = false;
        if (serverHandle >= 0) {
            GoBackend.awgTurnOff(serverHandle);
            serverHandle = -1;
        }
        Log.i(TAG, "Stopped");
    }

    public boolean isRunning() { return running && serverHandle >= 0; }

    public String getClientConfig(String endpoint) {
        return "[Interface]\n"
                + "PrivateKey = " + clientKeyPair.getPrivateKey().toBase64() + "\n"
                + "Address = " + CLIENT_TUNNEL_IP + "/32\n"
                + "DNS = 1.1.1.1\n\n"
                + "[Peer]\n"
                + "PublicKey = " + serverKeyPair.getPublicKey().toBase64() + "\n"
                + "Endpoint = " + endpoint + ":" + LISTEN_PORT + "\n"
                + "AllowedIPs = 0.0.0.0/0\n"
                + "PersistentKeepalive = 25\n";
    }

    private void generateKeys() {
        serverKeyPair = new KeyPair();
        clientKeyPair = new KeyPair();
    }

    private String buildServerIpcConfig() {
        // wireguard-go IPC format
        return "private_key=" + serverKeyPair.getPrivateKey().toHex() + "\n"
                + "listen_port=" + LISTEN_PORT + "\n"
                + "public_key=" + clientKeyPair.getPublicKey().toHex() + "\n"
                + "allowed_ip=0.0.0.0/0\n";
    }

    private static int[] createSocketPair() {
        try {
            android.os.ParcelFileDescriptor[] pair = android.os.ParcelFileDescriptor.createSocketPair();
            return new int[]{pair[0].detachFd(), pair[1].detachFd()};
        } catch (Exception e) {
            Log.e(TAG, "createSocketPair: " + e);
            return null;
        }
    }
}
