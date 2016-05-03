package com.example.vky.aes;
/**
 * File name : Activity1.java
 * Authors: Vikas Nandanam and Vikram Patil
 * Subject: Security Algorithms and Protocols
 * This file is activity file that displays the screen of the application.
 * This activity file displays the encryption procedure of the application.
 */

import android.app.AlertDialog;
import android.app.Application;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.graphics.Bitmap;
import android.media.AudioManager;
import android.media.SoundPool;
import android.os.Bundle;
import android.os.Message;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;


public class Activity1 extends AppCompatActivity {
    SoundPool mySound;
    int blip;

    Aescipher as = new Aescipher();

    public EditText editText;

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_encry);


        //This is decrypt button, on button click opens decrypt activity
        Button btnde = (Button) findViewById(R.id.buttonde);

        //This is back button, on click goes back to previous activity
        Button btnexit = (Button) findViewById(R.id.buttonexi);

        //This is encrypt button, on click calls encryption function
        Button btnenc = (Button) findViewById(R.id.buttonec);

        //This is text view that displays encrypted message
        final TextView ctext = (TextView) findViewById(R.id.textView3);

        //This is edit text field that takes key for encryption
        final EditText keytxt = (EditText) findViewById(R.id.keytxt);

        //This is text field that takes message to be encrypted
        final EditText paratxt = (EditText) findViewById(R.id.paratxt);

        //This is a image view that on click displays a image after encryption
        final ImageView enic = (ImageView) findViewById(R.id.imageView2);

        //Intializing sounds for the application
        mySound = new SoundPool(5, AudioManager.STREAM_MUSIC, 0);

        //Intializing sound
        blip = mySound.load(this, R.raw.blip2, 1);

        //Intializing clear button
        Button btnclear = (Button) findViewById(R.id.buttonclear);


        // This is Encrypt button which on Click calls encryption function in Aescipher.java file
        btnenc.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {


                //plays sound on button click
                mySound.play(blip, 1, 1, 1, 0, 1);

                String cipherText = "";
                // This is converts the entered key to string
                String keystr = keytxt.getText().toString().trim();
                if (TextUtils.isEmpty(keystr) || keystr.length() < 16) {
                    keytxt.setError("You have less than 16 characters in key");
                    return;
                }

                //This converts the entered text to string
                String parstr = paratxt.getText().toString().trim();
                if (TextUtils.isEmpty(parstr) || parstr.length() < 16) {
                    paratxt.setError("You have less than 16 characters in text");
                    return;
                }

                System.out.println("In string format: " + keystr);
                System.out.println("In text: " + parstr);


                cipherText = Aescipher.aes(keystr, parstr);
                enic.setVisibility(View.VISIBLE);
                ctext.setText(cipherText);

                // Writing the ecnrypted text into file
                try {
                    Context context = Activity1.this.getApplicationContext();


                    FileOutputStream fileOutputStream = openFileOutput("input", Context.MODE_PRIVATE);
                    fileOutputStream.write(cipherText.getBytes());

                    fileOutputStream.close();
                    FileWriter out = new FileWriter(new File(context.getFilesDir(), "textfile.txt"));
                    out.write(cipherText);
                    out.close();
                    Toast.makeText(getBaseContext(), "File saved successfully!", Toast.LENGTH_SHORT).show();
                } catch (Exception e) {
                    e.printStackTrace();
                }

            }

        });


        //This goes to new activity2 on button click
        btnde.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                mySound.play(blip, 1, 1, 1, 0, 1);

                Intent i = new Intent(getApplicationContext(), Activity2.class);
                startActivity(i);
                setContentView(R.layout.activity_decr);
            }
        });
        //This goes to main activity on button click
        btnexit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                mySound.play(blip, 1, 1, 1, 0, 1);
                finish();
                System.exit(0);
            }
        });

        //THis clears all the text fields and text views
        btnclear.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                mySound.play(blip, 1, 1, 1, 0, 1);
                ctext.setText("");
                keytxt.setText("");
                paratxt.setText("");
                enic.setImageResource(0);

            }
        });
    }

}
