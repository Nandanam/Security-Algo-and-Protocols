package com.example.vky.aes;
/**
 * File name : About.java
 * Authors: Vikas Nandanam and Vikram Patil
 * Subject: Security Algorithms and Protocols
 * This file is activity file that displays the  screen of the application.
 * This activity file displays the about page of the application.
 */

import android.content.Intent;
import android.media.AudioManager;
import android.media.SoundPool;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;


public class About extends AppCompatActivity {

    SoundPool mySound;
    int blip;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.about_layout);

        // Intializing Sound pool
        mySound = new SoundPool(5, AudioManager.STREAM_MUSIC, 0);

        //Intializing sound
        blip = mySound.load(this, R.raw.blip2, 1);

        //Intializing button back
        Button abt = (Button) findViewById(R.id.buttonabt);

        //This is displays the main screen of application
        abt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                mySound.play(blip, 1, 1, 1, 0, 1);
                Intent i = new Intent(getApplicationContext(), MainActivity.class);
                startActivity(i);
                setContentView(R.layout.activity_main);
            }
        });
    }
}
