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

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import android.os.Bundle;
import android.app.Activity;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

public class MainActivity extends Activity
{
	private EditText			textInput;
	private EditText			keyInput;
	private TextView			errorText;
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
		errorText = (TextView) findViewById(R.id.errorText);
		
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
						errorText.setText("Error:");
						errorText
								.setText("Please set your plaintext and key before encrypting.");
					}
					else
					{
						encrypter.prepareKeyForEncryption(keyText);
						encrypter.encryptWithAES(encrypter.getSecretKeyBytes(),
								inputText);
						textInput.setText(encrypter.getBase64CipherText());
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
				inputText = textInput.getText().toString();
				keyText = keyInput.getText().toString();
				
				try
				{
					if (encrypter.getBase64CipherText() == null)
					{
						errorText.setText("Error: ");
						errorText.setText("There is nothing to decrypt!");
					}
					else
					{
						encrypter.decryptAES(encrypter.getSecretKeyBytes(),
								inputText);
						textInput.setText(encrypter.getDecryptedText());
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

}