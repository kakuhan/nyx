package com.nyx.proxy;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;

/**
 * MainActivity — Entry point that starts NyxService as a foreground service.
 * 
 * The activity finishes immediately after starting the service.
 * All proxy logic lives in NyxService to survive background transitions.
 */
public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Intent serviceIntent = new Intent(this, NyxService.class);
        
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent);
        } else {
            startService(serviceIntent);
        }
        
        // Activity has no UI — finish immediately
        finish();
    }
}
