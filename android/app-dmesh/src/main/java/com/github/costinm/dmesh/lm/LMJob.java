package com.github.costinm.dmesh.lm;

import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;
import android.os.Build;
import android.os.SystemClock;
import android.util.Log;

//import wpgate.Wpgate;

import static android.app.job.JobScheduler.RESULT_SUCCESS;

import com.github.costinm.dmesh.lm3.LocalMesh;

/**
 *  LMJob runs avery 15min (min interval allowed).
 *  Will run an update cycle, possibly starting AP.
 *
 *  If the battery permissions/fg are not enabled this is the main discovery.
 */
public class LMJob extends JobService {
    private static final String TAG = "DMJob";

    static long lastStart;
    static boolean scheduled = false;

    public static void schedule(Context ctx, long interval) {
        if (scheduled) {
            return;
        }
        JobScheduler js = (JobScheduler) ctx.getSystemService(Context.JOB_SCHEDULER_SERVICE);
        js.cancel(1);
        Log.d(TAG, "Schedule periodic after " + interval/1000);

        if (interval > 0) {
            JobInfo.Builder b = new JobInfo.Builder(1, new ComponentName(
                    ctx.getPackageName(), LMJob.class.getName()))
                    .setPersisted(true)
                    .setPeriodic(interval);

            b.setRequiresBatteryNotLow(true);
            JobInfo  job = b.build();
            if (RESULT_SUCCESS == js.schedule(job)) {
                scheduled = true;
            }
        }
    }

    @Override
    public boolean onStartJob(final JobParameters params) {
        lastStart = SystemClock.elapsedRealtime();

        Runnable r = new Runnable() {
            @Override
            public void run() {
                LocalMesh lm = LocalMesh.get(LMJob.this.getApplicationContext());
                dmjni.Dmjni.update();
                lm.update();
                try {
                    Thread.sleep(5000);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
                Log.d(TAG, "LMJob " + params.getJobId());
                jobFinished(params, false);
            }
        };
        new Thread(r).start();
        return true;
    }

    public void onLowMemory() {
        Log.d(TAG, "On Low memory");
    }

    public void onTrimMemory(int level) {
        Log.d(TAG, "On Trim memory");
    }

    @Override
    public boolean onStopJob(JobParameters params) {
        Log.d(TAG, "LMJob stopped ");
        return false;
    }
}
