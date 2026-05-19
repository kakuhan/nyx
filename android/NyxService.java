package com.nyx.proxy;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import java.io.*;

/**
 * NyxService — Foreground service that runs the Nyx Go proxy binary.
 * 
 * Running as a foreground service (with persistent notification) prevents
 * Android from killing the proxy process when the activity is backgrounded.
 * 
 * Architecture:
 *   MainActivity → startService(NyxService) → finish()
 *   NyxService → startForeground(notification) → extract & run Go binary
 */
public class NyxService extends Service {
    private static final String CHANNEL_ID = "nyx_proxy";
    private static final int NOTIFICATION_ID = 1;
    private Process proxyProcess;

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Start as foreground service immediately (per Android 8+ requirement)
        Notification notification = buildNotification("Nyx tunnel starting...");
        startForeground(NOTIFICATION_ID, notification);

        startProxy();
        return START_STICKY; // Restart if killed
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null; // Not a bound service
    }

    @Override
    public void onDestroy() {
        if (proxyProcess != null) {
            proxyProcess.destroy();
            proxyProcess = null;
        }
        stopForeground(true);
        super.onDestroy();
    }

    // ── Notification helpers ──────────────────────────────────────────

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID, "Nyx Proxy",
                NotificationManager.IMPORTANCE_LOW  // Low = no sound, shows in shade
            );
            channel.setDescription("Nyx encrypted tunnel status");
            ((NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE))
                .createNotificationChannel(channel);
        }
    }

    private Notification buildNotification(String text) {
        // PendingIntent to re-open the activity when notification is tapped
        Intent intent = new Intent(this, MainActivity.class);
        PendingIntent pending = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT
        );

        Notification.Builder builder;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            builder = new Notification.Builder(this, CHANNEL_ID);
        } else {
            builder = new Notification.Builder(this);
        }

        return builder
            .setContentTitle("Nyx Proxy")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_menu_share)
            .setContentIntent(pending)
            .setOngoing(true) // Cannot be swiped away
            .build();
    }

    // ── Proxy lifecycle ───────────────────────────────────────────────

    private void startProxy() {
        try {
            // Android 10+ (API 29+) blocks exec() from app private data dir.
            // Solution: bundle binary as native lib (lib/arm64-v8a/libnyx.so)
            // → extracted by system to nativeLibraryDir (has exec permission).
            File binFile = new File(getApplicationInfo().nativeLibraryDir, "libnyx.so");
            if (!binFile.exists() || !binFile.canExecute()) {
                android.util.Log.e("Nyx", "Native binary not found or not executable: " + binFile);
                startForeground(NOTIFICATION_ID,
                    buildNotification("Nyx failed: binary not executable on this Android version"));
                stopSelf();
                return;
            }

            // Locate config: prefer /sdcard/nyx-client.json, fall back to bundled
            File cfgFile = new File(getFilesDir(), "nyx-client.json");
            File sdcardCfg = new File("/sdcard/nyx-client.json");
            if (sdcardCfg.exists()) {
                copyFile(sdcardCfg, cfgFile);
            } else {
                try {
                    copyAsset("nyx-client.json", cfgFile);
                } catch (IOException e) {
                    android.util.Log.w("Nyx", "No config found — using defaults");
                }
            }

            // Build command
            ProcessBuilder pb = new ProcessBuilder(
                binFile.getAbsolutePath(),
                "--config", cfgFile.getAbsolutePath()
            );
            pb.directory(getFilesDir());
            pb.redirectErrorStream(true);

            proxyProcess = pb.start();
            
            // Update notification
            startForeground(NOTIFICATION_ID,
                buildNotification("Nyx tunnel running — SOCKS5 :1080"));
            
            android.util.Log.i("Nyx", "Nyx proxy started");

            // Log stdout in background (anonymous Runnable, no lambda for Java 8 compat)
            new Thread(new Runnable() {
                public void run() {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(proxyProcess.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        android.util.Log.i("Nyx", line);
                    }
                } catch (IOException e) {
                    android.util.Log.w("Nyx", "Log reader ended: " + e.getMessage());
                }
                // Process exited — update notification
                startForeground(NOTIFICATION_ID,
                    buildNotification("Nyx tunnel stopped"));
                stopSelf();
                }  // run()
            }).start();  // Thread

        } catch (Exception e) {
            android.util.Log.e("Nyx", "Failed to start proxy", e);
            startForeground(NOTIFICATION_ID,
                buildNotification("Nyx failed: " + e.getMessage()));
        }
    }

    private void copyAsset(String assetPath, File dst) throws IOException {
        try (InputStream in = getAssets().open(assetPath);
             OutputStream out = new FileOutputStream(dst)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        }
    }

    private void copyFile(File src, File dst) throws IOException {
        try (InputStream in = new FileInputStream(src);
             OutputStream out = new FileOutputStream(dst)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        }
    }
}
