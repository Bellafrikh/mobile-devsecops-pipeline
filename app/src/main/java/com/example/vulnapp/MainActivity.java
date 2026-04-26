package com.example.vulnapp;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.webkit.WebView;

public class MainActivity extends Activity {

    // VULN 1 : Hardcoded credentials (CWE-798)
    private static final String API_KEY = "sk-prod-12345ABCDEF";
    private static final String DB_PASSWORD = "admin123";
    private static final String SECRET_TOKEN = "ghp_abcdefgh123456789";

    // VULN 2 : Hardcoded IP / HTTP non sécurisé
    private static final String SERVER_URL = "http://192.168.1.100/api";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // VULN 3 : Log de données sensibles (CWE-532)
        Log.d("DEBUG", "User password: " + DB_PASSWORD);
        Log.d("DEBUG", "API Key: " + API_KEY);
        Log.d("DEBUG", "Token: " + SECRET_TOKEN);

        // VULN 4 : SQL Injection (CWE-89)
        String userInput = getIntent().getStringExtra("username");
        String query = "SELECT * FROM users WHERE name = '" + userInput + "'";
        Log.d("SQL", "Query: " + query);

        // VULN 5 : WebView JavaScript activé sans protection
        WebView webView = new WebView(this);
        webView.getSettings().setJavaScriptEnabled(true);
        webView.loadUrl(SERVER_URL);
    }
}