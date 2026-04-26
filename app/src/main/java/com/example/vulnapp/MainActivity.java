package com.example.vulnapp;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.webkit.WebView;

public class MainActivity extends Activity {

    // VULN 1 : Credentials hardcodés dans le code (CWE-798)
    private static final String API_KEY    = "sk-prod-12345ABCDEF";
    private static final String DB_PASS    = "admin123";
    private static final String SECRET_TOK = "ghp_abcdefgh123456789";

    // VULN 2 : URL HTTP non sécurisée + IP hardcodée
    private static final String SERVER_URL = "http://192.168.1.100/api";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // VULN 3 : Données sensibles écrites dans les logs (CWE-532)
        Log.d("DEBUG", "Password: " + DB_PASS);
        Log.d("DEBUG", "API Key: " + API_KEY);
        Log.d("DEBUG", "Token: "   + SECRET_TOK);

        // VULN 4 : Injection SQL par concaténation (CWE-89)
        String userInput = getIntent().getStringExtra("username");
        String query = "SELECT * FROM users WHERE name = '" + userInput + "'";
        Log.d("SQL", "Query: " + query);

        // VULN 5 : WebView avec JavaScript activé sans protection
        WebView wv = new WebView(this);
        wv.getSettings().setJavaScriptEnabled(true);
        wv.loadUrl(SERVER_URL);
    }
}