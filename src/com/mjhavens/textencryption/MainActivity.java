/*
 * @author: MJ Havens
 * 
 * This is the main activity that gets called when the app starts. 
 * It is used to control input and output on the GUI while interacting with EncryptionActivity.
 */

package com.mjhavens.textencryption;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import android.os.Bundle;
import android.app.Activity;
import android.graphics.Color;
import android.util.Log;
import android.view.Menu;
import android.view.View;
import android.view.View.OnClickListener;
import android.webkit.WebView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

public class MainActivity extends Activity
{
	private EditText			textInput;
	private EditText			keyInput;
	private TextView			outputText;
	private TextView			cryptedText;
	private Button				encrypt;
	private Button				decrypt;
	private String				inputText	= null;
	private String				keyText		= null;
	private EncryptionActivity	encrypter;

	@Override
	protected void onCreate(Bundle savedInstanceState)
	{

		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_encryption);

		// Declare View IDs.
		encrypter = new EncryptionActivity();
		textInput = (EditText) findViewById(R.id.textInput);
		encrypt = (Button) findViewById(R.id.btnEncrypt);
		decrypt = (Button) findViewById(R.id.btnDecrypt);
		keyInput = (EditText) findViewById(R.id.keyInput);
		outputText = (TextView) findViewById(R.id.outputText);
		cryptedText = (TextView) findViewById(R.id.cryptedText);

		
		// Sets the listener each time the encrypt button is hit.
		encrypt.setOnClickListener(new View.OnClickListener()
		{

			@Override
			public void onClick(View v)
			{
				Log.d("App", "Clicked encrypt");
				inputText = textInput.getText().toString();
				keyText = keyInput.getText().toString();
				try
				{
					if (inputText.isEmpty() || keyText.isEmpty())
					{
						cryptedText.setText("Error:");
						outputText
								.setText("Please set your plaintext and key before encrypting.");
					}
					else
					{
						cryptedText.setText("AES/Base 64 Cipher Text:");
						encrypter.prepareKeyForEncryption(keyText);
						encrypter.encryptWithAES(encrypter.getSecretKeyBytes(),
								inputText);
						outputText.setText(encrypter.getBase64CipherText());
					}
				}
				catch (Exception e)
				{
					e.printStackTrace();
				}
			}
		});

		// Sets the listener each time the decrypt button is hit.
		decrypt.setOnClickListener(new View.OnClickListener()
		{
			@Override
			public void onClick(View v)
			{
				Log.d("App", "Click decrypt");

				try
				{
					if (encrypter.getBase64CipherText() == null)
					{
						cryptedText.setText("Error: ");
						outputText.setText("There is nothing to decrypt!");
					}
					else
					{
						cryptedText.setText("Plaintext:");
						encrypter.decryptAES(encrypter.getSecretKeyBytes(),
								encrypter.getBase64CipherText());
						outputText.setText(encrypter.getDecryptedText());
					}
				}
				catch (Exception e)
				{
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		});
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu)
	{
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.encryption, menu);
		return true;
	}

}