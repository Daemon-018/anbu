package com.anbu.scanner;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInstaller;
import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;

import java.io.File;

/**
 * Receives the outcome of a PackageInstaller session.
 */
public final class InstallResultReceiver extends BroadcastReceiver {

    public static final String EXTRA_SESSION_DIR = "com.anbu.scanner.SESSION_DIR";

    @Override
    public void onReceive(Context context, Intent intent) {
        int status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE);
        File dir = (File) intent.getParcelableExtra(EXTRA_SESSION_DIR);

        if (status == PackageInstaller.STATUS_SUCCESS) {
            Toast.makeText(context, "App installed successfully", Toast.LENGTH_SHORT).show();
        } else if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) {
            Intent confirmationIntent = intent.getParcelableExtra(Intent.EXTRA_INTENT);
            if (confirmationIntent != null) {
                confirmationIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                context.startActivity(confirmationIntent);
            }
        } else {
            String msg = "Installation failed: " + status;
            if (intent.hasExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)) {
                msg += " (" + intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) + ")";
            }
            Toast.makeText(context, msg, Toast.LENGTH_LONG).show();
        }

        // Terminal cleanup of the cached installation set.
        if (dir != null) {
            InstallSet.delete(dir);
        }
    }
}
