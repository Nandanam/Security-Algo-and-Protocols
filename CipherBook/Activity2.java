package com.example.vky.aes;
/**
 * File name : Activity2.java
 * Authors: Vikas Nandanam and Vikram Patil
 * Subject: Security Algorithms and Protocols
 * This file is activity file that displays the screen of the application.
 * This activity file displays the decryption procedure of the application.
 */

import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.media.AudioManager;
import android.media.SoundPool;
import android.os.Bundle;
import android.os.Process;
import android.provider.ContactsContract;
import android.provider.Settings;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;


public class Activity2 extends AppCompatActivity {

    SoundPool mySound;
    int blip;

    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);

        //Intializing sound for the application
        mySound = new SoundPool(5, AudioManager.STREAM_MUSIC, 0);
        blip = mySound.load(this, R.raw.blip2, 1);

        setContentView(R.layout.activity_decr);
        //This is a edit text field that takes key
        final EditText deckey = (EditText) findViewById(R.id.editTextdec);

        //This is a text view to display plain text
        final TextView pltxt = (TextView) findViewById(R.id.textView5);

        //This is decrypt button,on click calls decryption function
        Button btndec = (Button) findViewById(R.id.buttondec);

        //This is back button, on click goes to previous activity
        Button btndq = (Button) findViewById(R.id.buttondq);

        //Intializing clear button
        Button btnclearr = (Button) findViewById(R.id.buttonclearr);

        //Intializing read button
        Button btnred = (Button) findViewById(R.id.buttonred);

        //Initializing exit button
        Button btnx = (Button) findViewById(R.id.buttonx);

        //Intializing edit text for cipher text
        final EditText cip = (EditText) findViewById(R.id.editTextCip);

        //This is an image view on button click will display an image
        final ImageView decim = (ImageView) findViewById(R.id.imageViewunloc);

        //Button on click decrypts the cipher text
        btndec.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {


                //plays sound on button click
                mySound.play(blip, 1, 1, 1, 0, 1);

                String cipherText = "";
                String keydstr = deckey.getText().toString().trim();
                if (TextUtils.isEmpty(keydstr) || keydstr.length() < 16) {
                    deckey.setError("You have less than 16 characters in key");
                    return;
                }

                String cipstr = cip.getText().toString().trim();

                System.out.println("In deck format: " + keydstr);
                System.out.println("In cip text: " + cipstr);

                Decryption d = new Decryption();
                cipherText = d.aes(keydstr, cipstr);
                pltxt.setText(cipherText);
                decim.setVisibility(View.VISIBLE);
                System.out.print("Dec: " + cipherText);

            }
        });

        //This is back button on click goes to activity1
        btndq.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                mySound.play(blip, 1, 1, 1, 0, 1);

                finish();
                System.exit(0);
            }
        });

        //This is clear button on click clears all the text fields
        btnclearr.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                mySound.play(blip, 1, 1, 1, 0, 1);
                deckey.setText("");
                pltxt.setText("");
                cip.setText("");
                decim.setImageResource(0);
            }
        });

        //This is a read button on click reads the file
        btnred.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                mySound.play(blip, 1, 1, 1, 0, 1);

                //Reading file
                try {
                    BufferedReader inputReader = new BufferedReader(new InputStreamReader(openFileInput("input")));
                    String inputString;
                    StringBuffer stringBuffer = new StringBuffer();
                    while ((inputString = inputReader.readLine()) != null) {
                        stringBuffer.append(inputString + "\n");
                        cip.setText(stringBuffer.toString());
                    }

                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });

        //Exit button to close application
        btnx.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                finish();
            }
        });
    }

    protected void onDestroy() {
        Process.killProcess(Process.myPid());
        super.onDestroy();
    }
}
