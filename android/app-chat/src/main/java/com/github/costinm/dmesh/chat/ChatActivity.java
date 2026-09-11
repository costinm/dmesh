package com.github.costinm.dmesh.chat;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.view.WindowInsets;

public class ChatActivity extends Activity {
    private EguiSurfaceView surfaceView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        surfaceView = new EguiSurfaceView(this);
        setContentView(surfaceView);

        // Listen for window insets (keyboard height)
        surfaceView.setOnApplyWindowInsetsListener(new View.OnApplyWindowInsetsListener() {
            @Override
            public WindowInsets onApplyWindowInsets(View v, WindowInsets insets) {
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
                    android.graphics.Insets imeInsets = insets.getInsets(WindowInsets.Type.ime());
                    surfaceView.setBottomInset(imeInsets.bottom);
                }
                return insets;
            }
        });
    }

    @Override
    protected void onDestroy() {
        if (surfaceView != null) {
            surfaceView.destroy();
        }
        super.onDestroy();
    }
}
