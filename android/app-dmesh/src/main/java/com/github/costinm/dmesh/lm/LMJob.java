package com.github.costinm.dmesh.lm;

import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;
import android.os.Build;
import android.os.SystemClock;
import androidx.annotation.RequiresApi;
import android.util.Log;

//import wpgate.Wpgate;

import static android.app.job.JobScheduler.RESULT_SUCCESS;

/**
 *  LMJob runs avery 15min (min interval allowed).
 *  Will run an update cycle, possibly starting AP.
 *
 *  If the battery permissions/fg are not enabled this is the main discovery.
 */
@RequiresApi(api = Build.VERSION_CODES.LOLLIPOP)
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

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                b.setRequiresBatteryNotLow(true);
            }
            JobInfo  job = b.build();
            if (RESULT_SUCCESS == js.schedule(job)) {
                scheduled = true;
            }
        }
    }

    public static void scheduleAfter(Context ctx, long interval) {
        JobScheduler js = (JobScheduler) ctx.getSystemService(Context.JOB_SCHEDULER_SERVICE);
        js.cancel(2);
        Log.d(TAG, "Schedule update after " + interval/1000);

        if (interval > 0) {
            JobInfo.Builder b = new JobInfo.Builder(2, new ComponentName(
                    ctx.getPackageName(), LMJob.class.getName()));

            b.setMinimumLatency(interval);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                b.setRequiresBatteryNotLow(true);
            }

            JobInfo  job = b.build();
            js.schedule(job);
        }
    }

    @Override
    public boolean onStartJob(final JobParameters params) {
        lastStart = SystemClock.elapsedRealtime();
        Log.d(TAG, "LMJob " + params.getJobId());

        Runnable r = new Runnable() {
            @Override
            public void run() {
                //Wpgate.update();
                jobFinished(params, false);
            }
        };
        new Thread(r).start();
        return true;
    }

    @Override
    public boolean onStopJob(JobParameters params) {
        Log.d(TAG, "LMJob stopped ");
        return false;
    }
}
