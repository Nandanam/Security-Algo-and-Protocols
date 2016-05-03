package com.example.vky.aes;
/**
 * File name : MainActivity.java
 * Authors: Vikas Nandanam and Vikram Patil
 * Subject: Security Algorithms and Protocols
 * This file is activity file that displays the  main screen of the application.
 * This activity file displays the start screen of the application.
 */

import android.content.Intent;
import android.media.AudioManager;
import android.media.SoundPool;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;

public class MainActivity extends AppCompatActivity {
    SoundPool mySound;
    int blip;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        //Intializing start button
        Button btn1 = (Button) findViewById(R.id.button1);

        //Intializing Sounds
        mySound = new SoundPool(5, AudioManager.STREAM_MUSIC, 0);
        blip = mySound.load(this, R.raw.blip2, 1);

        // Intializing button for about
        Button btnabtp = (Button) findViewById(R.id.buttonabtp);

        //This is a button click which starts the application
        btn1.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                mySound.play(blip, 1, 1, 1, 0, 1);
                Intent i = new Intent(getApplicationContext(), Activity1.class);
                startActivity(i);
                setContentView(R.layout.activity_encry);
            }
        });

        //This is button click which displays about the application
        btnabtp.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                mySound.play(blip, 1, 1, 1, 0, 1);
                Intent i = new Intent(getApplicationContext(), About.class);
                startActivity(i);
                setContentView(R.layout.about_layout);
            }
        });
    }


}
