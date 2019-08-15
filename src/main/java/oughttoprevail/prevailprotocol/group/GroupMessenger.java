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
package oughttoprevail.prevailprotocol.group;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

import oughttoprevail.prevailprotocol.User;
import oughttoprevail.prevailprotocol.asymmetriccryptography.AsymmetricCryptography;
import oughttoprevail.prevailprotocol.cipher.MessengerCipher;
import oughttoprevail.prevailprotocol.doubleratchet.SymmetricKeyRatchet;
import oughttoprevail.prevailprotocol.exception.CounterTooLargeException;
import oughttoprevail.prevailprotocol.messenger.MessageKeys;
import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.SkippedKeysStorage;
import oughttoprevail.prevailprotocol.util.Util;

/**
 * A {@link Group} messenger (encrypts and decrypts messages).
 */
class GroupMessenger
{
	/**
	 * Cipher used for encryption
	 */
	private final MessengerCipher cipher;
	/**
	 * Session who created this messenger
	 */
	private final GroupSession session;
	/**
	 * Storage for skipped keys
	 */
	private final SkippedKeysStorage skippedKeysStorage;
	/**
	 * Settings to use
	 */
	private final Settings settings;
	
	/**
	 * Constructs a new {@link GroupMessenger}
	 *
	 * @param user who created the {@link Group}
	 * @param session who is creating this
	 * @param skippedKeysStorage to store skipped keys in
	 * @param settings to use
	 */
	GroupMessenger(User user, GroupSession session, SkippedKeysStorage skippedKeysStorage, Settings settings)
	{
		this.session = session;
		this.cipher = user.getCipher();
		this.skippedKeysStorage = skippedKeysStorage;
		this.settings = settings;
	}
	
	/**
	 * Encrypts the specified message.
	 *
	 * The encrypted message format is:
	 * <ul>
	 *     <li>{@link Util#INT_BYTES} bytes - int - counter of sending {@link SymmetricKeyRatchet} before the step in
	 *     this encryption</li>
	 *     <li>{@link AsymmetricCryptography#getSignatureSize()} bytes - byte[] - ciphertext signature</li>
	 *     <li>{@link Util#INT_BYTES} bytes - int - ciphertext length</li>
	 *     <li>ciphertext length - byte[] - ciphertext</li>
	 * </ul>
	 *
	 * @param message to encrypt
	 * @return the encrypted message
	 */
	byte[] encryptMessage(byte[] message)
			throws InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException
	{
		SymmetricKeyRatchet sendingRatchet = session.getSendingRatchet();
		byte[] counterBytes = sendingRatchet.getCounterBytes();
		MessageKeys messageKeys = sendingRatchet.step(false);
		byte[] ciphertext = cipher.encrypt(messageKeys.getMessageKey(), messageKeys.getIV(), message);
		byte[] signature = settings.getAsymmetricCryptography().sign(ciphertext, session.getSignatureKeyPair().getPrivateKey());
		return Util.combine(counterBytes, signature, Util.intToBytes(ciphertext.length), ciphertext);
	}
	
	/**
	 * Decrypts the specified ciphertext using the specified parameters.
	 *
	 * @param receivedCounter is the sender's counter of the symmetric ratchet before the {@link MessageKeys} used to encrypt the specified ciphertext
	 * were generated
	 * @param ciphertext to decrypt
	 * @param senderSignatureNRatchet the sender's {@link SignatureNRatchet}
	 * @return the decrypted (plaintext) message
	 */
	byte[] decryptMessage(int receivedCounter, byte[] ciphertext, SignatureNRatchet senderSignatureNRatchet)
			throws CounterTooLargeException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException
	{
		MessageKeys messageKeys = null;
		byte[] signatureKey = senderSignatureNRatchet.getSignatureKey();
		if(skippedKeysStorage != null)
		{
			messageKeys = skippedKeysStorage.getSkippedMessageKeys(signatureKey, receivedCounter);
		}
		if(messageKeys == null)
		{
			SymmetricKeyRatchet receivingRatchet = senderSignatureNRatchet.getReceivingRatchet();
			skipKeys(signatureKey, receivedCounter, receivingRatchet);
			messageKeys = receivingRatchet.step(false);
		}
		return cipher.decrypt(messageKeys.getMessageKey(), messageKeys.getIV(), ciphertext);
	}
	
	/**
	 * Skips keys in the specified receivingRatchet until the {@link SymmetricKeyRatchet#getCounter()} equals the specified receivedCounter
	 *
	 * @param publicSignatureKey to be the key identifier of the skipped key
	 * @param receivedCounter to skip to
	 * @param receivingRatchet to skip keys in
	 */
	private void skipKeys(byte[] publicSignatureKey, int receivedCounter, SymmetricKeyRatchet receivingRatchet)
			throws CounterTooLargeException, InvalidKeyException
	{
		int myCounter = receivingRatchet.getCounter();
		if(SkippedKeysStorage.ensureCanSkip(skippedKeysStorage, myCounter, receivedCounter, settings))
		{
			return;
		}
		while(myCounter < receivedCounter)
		{
			skippedKeysStorage.addSkippedKey(publicSignatureKey, null, myCounter, receivingRatchet.step());
			myCounter++;
		}
		skippedKeysStorage.flush();
	}
}