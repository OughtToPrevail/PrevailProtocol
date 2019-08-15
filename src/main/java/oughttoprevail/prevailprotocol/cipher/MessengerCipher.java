/*
PrevailProtocol.
Copyright (C) 2019  https://github.com/OughtToPrevail

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
package oughttoprevail.prevailprotocol.cipher;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.util.IvSpec;
import oughttoprevail.prevailprotocol.util.KeySpec;

/**
 * A simple {@link Cipher} wrapper for easy operations.
 *
 * @see Cipher
 */
public class MessengerCipher
{
	/**
	 * Cipher to encrypt and decrypt with
	 */
	private final Cipher cipher;
	
	/**
	 * Constructs a new {@link MessengerCipher} with the specified settings.
	 *
	 * @param settings to create a cipher with
	 * @throws NoSuchPaddingException if the padding in the specified {@link Settings#getCipherAlgorithm()} doesn't exist
	 * @throws NoSuchAlgorithmException if the algorithm in the specified {@link Settings#getCipherAlgorithm()} doesn't exist
	 */
	public MessengerCipher(Settings settings) throws NoSuchPaddingException, NoSuchAlgorithmException
	{
		String cipherAlgorithm = settings.getCipherAlgorithm();
		Provider provider = settings.getProvider();
		cipher = provider == null ? Cipher.getInstance(cipherAlgorithm) : Cipher.getInstance(cipherAlgorithm, provider);
	}
	
	/**
	 * Invokes {@link #encrypt(KeySpec, IvSpec, byte[], byte[][])} with the {@code aad} set to {@code null}.
	 */
	public byte[] encrypt(KeySpec key, IvSpec iv, byte[] message)
			throws IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException
	{
		return encrypt(key, iv, message, null);
	}
	
	/**
	 * Encrypts the specified message with the specified key and specified iv.
	 * If the specified aad (additional authentication data) is not {@code null} then it should be updated in encryption.
	 *
	 * @param key to encrypt with
	 * @param iv to use in encryption
	 * @param message to encrypt
	 * @param aad to update in encryption, this may be {@code null}
	 * @return the ciphertext (encrypted message)
	 */
	public byte[] encrypt(KeySpec key, IvSpec iv, byte[] message, byte[]... aad)
			throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException
	{
		return doFinal(Cipher.ENCRYPT_MODE, key, iv, message, aad);
	}
	
	/**
	 * Invokes {@link #decrypt(KeySpec, IvSpec, byte[], byte[][])} with the {@code aad} set to {@code null}.
	 */
	public byte[] decrypt(KeySpec key, IvSpec iv, byte[] ciphertext)
			throws IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException
	{
		return decrypt(key, iv, ciphertext, null);
	}
	
	/**
	 * Decrypts the specified ciphertext with the specified key and specified iv.
	 * If the specified aad (additional authentication data) is not {@code null} then it should be updated in decryption.
	 *
	 * @param key to decrypt with
	 * @param iv to use in decryption
	 * @param ciphertext to decrypt
	 * @param aad to update in decryption, this may be {@code null}
	 * @return the decrypted message
	 */
	public byte[] decrypt(KeySpec key, IvSpec iv, byte[] ciphertext, byte[]... aad)
			throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException
	{
		return doFinal(Cipher.DECRYPT_MODE, key, iv, ciphertext, aad);
	}
	
	/**
	 * Performs a {@link Cipher#doFinal(byte[])} operation on the specified bytes after initializing it with the specified mode, key, iv and aad
	 *
	 * @param mode of the cipher
	 * @param key for the cipher
	 * @param iv for the cipher
	 * @param bytes to provide for the doFinal operation (if encrypt then bytes to be encrypted, if decrypt then bytes to be decrypted)
	 * @param aad additional authentication data (possibly {@code null} if there aren't any)
	 */
	private byte[] doFinal(int mode, KeySpec key, IvSpec iv, byte[] bytes, byte[]... aad)
			throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException
	{
		//set the specified mode, key and iv
		cipher.init(mode, key, iv);
		//if the aad isn't null, update it with the cipher
		if(aad != null)
		{
			for(byte[] aAAD : aad)
			{
				cipher.updateAAD(aAAD);
			}
		}
		//do final operation (encrypt/decrypt)
		return cipher.doFinal(bytes);
	}
}