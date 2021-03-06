package com.github.costinm.dmesh.android.util;

import android.content.Context;
import android.os.SystemClock;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.List;

/**
 * Run a native process. Optional restart and suspend/resume.
 */
public class NativeProcess extends Thread {
    // Wait before restarting.
    public static final int RESTART_DELAY = 5000;

    public static final String TAG = "DM-nat";
    final List<String> cmd;
    // Cmd to start the process
    private final String exec;
    private final Context ctx;
    public boolean keepAlive = false;
    // Null when not running
    Process p;

    /**
     * Start the native command.
     */
    public NativeProcess(Context ctx, String file, List<String> cmd) {
        this.cmd = cmd;
        this.ctx = ctx;
        this.exec = file;
        cmd.add(0, "");
        setName(file);
    }

    static void logStream(InputStream input, boolean isErr)
            throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(input));
        while (true) {
            String l = br.readLine();
            if (l == null) {
                Log.d("DM-N", "Closed");
                return;
            }
            if (isErr) {
                String[] parts = l.split(" ", 3);
                if (parts.length < 3) {
                    Log.d("DM-N", l);
                } else {
                    // skip timestamp
                    Log.d("DM-N", parts[2]);
                }
            } else {
                Log.d("DM-NO", l);
            }
        }
    }

    // Based on the 'exec' base name, try to upgrade by using externals dir or files dir.
    // Then if the exec is find in files, use it from there.
    // Last use the bundled exec from lib.Ma
    String getExecutable() {
        String nativeLib = ctx.getApplicationInfo().nativeLibraryDir;
        System.out.println("NATIVE LIBDIR: " + nativeLib);

//        final File srcDir = ctx.getExternalFilesDir(null);
//        File src = new File(srcDir, exec);
//
//        final File f = ctx.getFilesDir();
//        if (!src.exists()) {
//            src = new File(f, exec + ".new");
//        }
//        final File f2 = new File(f, exec);
//
//        if (src.exists()) {
//            try {
//                OutputStream fos = new FileOutputStream(f2);
//                InputStream fis = new FileInputStream(src);
//                copyStream(fis, fos);
//                fis.close();
//                fos.close();
//
//                src.delete();
//                f2.setExecutable(true);
//            } catch (IOException e) {
//                e.printStackTrace();
//            }
//        }
//
//        File d = ctx.getFilesDir();
//        File bin = new File(d, exec);
//
//        if (bin.exists() && bin.canExecute()) {
//            return bin.getAbsolutePath();
//        }

        return nativeLib + "/" + exec; //d.getParent() + "/lib/" + exec;
    }

    public void kill() {
        synchronized (NativeProcess.class) {
            Log.d(TAG, "Kill process" + p);
            if (p != null) {
                p.destroy();
                p = null;
            }
        }
    }

    public void run() {
        if (keepAlive) {
            while (keepAlive) {
                runOnce();

                try {
                    // Wait before restart
                    Thread.sleep(RESTART_DELAY);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        } else {
            runOnce();
        }
    }

    public void runOnce() {
        long t0 = SystemClock.elapsedRealtime();
        String exe = getExecutable();
        final File filesDir = ctx.getFilesDir();
        try {
            InputStream err;
            //InputStream out;
            synchronized (NativeProcess.class) {
                cmd.set(0, exe);
                ProcessBuilder pb = new ProcessBuilder().command(cmd).redirectErrorStream(true);
                pb.environment().put("STORAGE", ctx.getExternalFilesDir(null).getAbsolutePath());
                pb.environment().put("BASE", ctx.getFilesDir().getAbsolutePath());
                p = pb.start();
                err = p.getInputStream();
                //err = p.getErrorStream();
            }
            logStream(err, true); // will block until process is closed.
            // TODO: feed this into the mux ?
            //logStream(out, false); // will block until process is closed.
        } catch (Throwable t) {
            Log.d("DM-N", "Stopping !!" + t.getMessage());
        } finally {

            Log.d("DM-N", "Make sure it is killed !!");
            kill();
            long since = SystemClock.elapsedRealtime() - t0;
            if (since < 1000) {
                if (exe.startsWith(filesDir.getAbsolutePath())) {
                    Log.d("DM-N", "Bad upgrade !!");
                    new File(exe).delete();
                }
            }
        }
    }

    // No longer working in Q+ - exec permissions
//
//    public void upgrade(String url) {
//        try {
//            URLConnection urlc = new URL(url).openConnection();
//            InputStream is = urlc.getInputStream();
//            File d = ctx.getFilesDir();
//            File bin = new File(d, exec);
//            OutputStream os = new FileOutputStream(bin);
//            copyStream(is, os);
//            os.close();
//            is.close();
//            bin.setExecutable(true);
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }
//
//    public void upgrade(final Context ctx, String vpn, String fbase) {
//        final File f = ctx.getExternalFilesDir(null);
//        final File f2 = new File(f, fbase);
//
//        if (vpn == null) {
//            final File fd = ctx.getFilesDir();
//            new File(fd, fbase).delete();
//            return;
//        }
//
//        ctx.registerReceiver(new BroadcastReceiver() {
//            @Override
//            public void onReceive(Context context, Intent intent) {
//                Log.d(TAG, "Downloaded " + intent  + " " + f2.exists() + " " + f2.getAbsolutePath());
//                ctx.unregisterReceiver(this);
//
//                kill();
//
//                // TODO: override the old file
//            }
//        }, new IntentFilter(DownloadManager.ACTION_DOWNLOAD_COMPLETE));
//
//
//        // TODO: arch from platform
//        String url = "https://" + vpn + "/www/jniLibs/armeabi/" + fbase;
//
//        DownloadManager.Request request = new DownloadManager.Request(Uri.parse(url));
//        request.setDescription("DMesh download");
//        request.setTitle("DMesh VPN");
//
//        // in order for this if to run, you must use the android 3.2 to compile your app
//        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.HONEYCOMB) {
//            request.setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE);
//        }
//        Uri dest = Uri.withAppendedPath(Uri.fromFile(f), "libDM.so");
//        request.setDestinationUri(dest);
//
//        request.setVisibleInDownloadsUi(false);
//
//        Log.d(TAG, "Start: " + f2.getAbsolutePath() + " " + dest);
//
//        // dial download service and enqueue file
//        DownloadManager manager = (DownloadManager) ctx.getSystemService(Context.DOWNLOAD_SERVICE);
//        manager.enqueue(request);
//    }

}
