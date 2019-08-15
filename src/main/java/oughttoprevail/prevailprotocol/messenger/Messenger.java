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
package oughttoprevail.prevailprotocol.messenger;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Iterator;

import oughttoprevail.prevailprotocol.User;
import oughttoprevail.prevailprotocol.asymmetriccryptography.AsymmetricCryptography;
import oughttoprevail.prevailprotocol.cipher.MessengerCipher;
import oughttoprevail.prevailprotocol.doubleratchet.HeaderKeyRatchet;
import oughttoprevail.prevailprotocol.doubleratchet.SymmetricKeyRatchet;
import oughttoprevail.prevailprotocol.exception.CounterTooLargeException;
import oughttoprevail.prevailprotocol.exception.MissingMatchingHeaderKeyException;
import oughttoprevail.prevailprotocol.exception.MissingSkippedKeyException;
import oughttoprevail.prevailprotocol.exception.TooManyDevicesException;
import oughttoprevail.prevailprotocol.exception.VerificationFailedException;
import oughttoprevail.prevailprotocol.keys.SkippedKey;
import oughttoprevail.prevailprotocol.nonce.NonceGenerator;
import oughttoprevail.prevailprotocol.nonce.RatchetNonceGenerator;
import oughttoprevail.prevailprotocol.session.Session;
import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.SkippedKeysStorage;
import oughttoprevail.prevailprotocol.uid.UserDeviceUID;
import oughttoprevail.prevailprotocol.util.Consumer;
import oughttoprevail.prevailprotocol.util.IvSpec;
import oughttoprevail.prevailprotocol.util.KeySpec;
import oughttoprevail.prevailprotocol.util.Util;

/**
 * A {@link Messenger} encrypts and decrypts messages while following the many options set in the constructor specified {@link Settings}.
 */
public class Messenger
{
	/**
	 * User this {@link Messenger} is for
	 */
	private final User user;
	/**
	 * To encrypt and decrypt messages with
	 */
	private final MessengerCipher cipher;
	/**
	 * To authenticate messages
	 */
	private final Mac mac;
	/**
	 * The identifiers of the recipient
	 */
	private final UserDeviceUID userDeviceUID;
	/**
	 * The session this messenger uses.
	 * The session may be {@code null}, if it is, only decryption with a registerMessage specified is allowed
	 */
	private Session session;
	/**
	 * A nonce generator, used when operating with header encryption to generate a nonce for the header
	 */
	private final NonceGenerator nonceGenerator;
	/**
	 * The settings for this messenger
	 */
	private final Settings settings;
	
	/**
	 * Constructs a new {@link Messenger} for the specified user using the specified session with the specified settings.
	 *
	 * @param user who is creating this messenger
	 * @param session is the previously established session for this messenger to use
	 * @param settings to use
	 */
	public Messenger(User user, Session session, Settings settings)
	{
		this(user, null, session, settings);
	}
	
	/**
	 * Constructs a new {@link Messenger} for the specified user, userId, deviceId with the specified settings.
	 *
	 * @param user who is creating this messenger
	 * @param userDeviceUID is the recipient identifiers
	 * @param settings to use
	 */
	public Messenger(User user, UserDeviceUID userDeviceUID, Settings settings)
	{
		this(user, userDeviceUID, null, settings);
	}
	
	/**
	 * Constructs a new {@link Messenger} for the specified user, deviceId, session, settings.
	 *
	 * @param user who is creating this messenger
	 * @param userDeviceUID is the recipient user identifiers, ({@code null} if a session is specified)
	 * @param session is the previously established session for this messenger to use ({@code null} if a session is not available, tho if it is
	 * {@code null} then the userId and deviceId must not be {@code null})
	 * @param settings to use
	 */
	private Messenger(User user, UserDeviceUID userDeviceUID, Session session, Settings settings)
	{
		this.user = user;
		this.userDeviceUID = userDeviceUID;
		this.cipher = user.getCipher();
		this.mac = user.getMac();
		this.nonceGenerator = settings.isUseHeaderEncryption() ? new RatchetNonceGenerator(settings)
		{
			protected Session getSession()
			{
				return session;
			}
		} : null;
		this.session = session;
		this.settings = settings;
	}
	
	/**
	 * Encrypts the specified message.
	 *
	 * If {@link Settings#isUseHeaderEncryption()} is {@code true} then the encrypted message format is:
	 * <ul>
	 * <li>{@link Util#BYTE_BYTES} bytes - boolean - whether this message has register message</li>
	 * </ul>
	 * if this message has a register message then:
	 * <ul>
	 * <ul>
	 * <li>{@link Util#INT_BYTES} bytes - int - length of register message</li>
	 * <li>length of register message - byte[] - register message</li>
	 * </ul>
	 * </ul>
	 * if {@link Settings#isUseUpdateAAD()} is {@code true} then:
	 * <ul>
	 * <ul>
	 * <li>{@link Settings#getMessageMacSize()} bytes - byte[] - encrypted header mac</li>
	 * </ul>
	 * <li>{@link Settings#getIVSize()} bytes - byte[] - encrypted header nonce</li>
	 * <li>{@link Util#INT_BYTES} bytes - int - length of encrypted header</li>
	 * <li>length of encrypted header - byte[] - encrypted header</li>
	 * <li>{@link Util#INT_BYTES} bytes - int - length of ciphertext</li>
	 * <li>length of ciphertext - byte[] - ciphertext</li>
	 * </ul>
	 *
	 * else if {@link Settings#isUseHeaderEncryption()} is {@code false} then the encrypted message format is:
	 * <ul>
	 * <li>{@link Util#BYTE_BYTES} bytes - boolean - whether this message has register message</li>
	 * </ul>
	 * if this message has a register message then:
	 * <ul>
	 * <ul>
	 * <li>{@link Util#INT_BYTES} bytes - int - length of register message</li>
	 * <li>length of register message - byte[] - register message</li>
	 * </ul>
	 * <li>{@link Util#INT_BYTES} bytes - int - counter of sending {@link SymmetricKeyRatchet} before the step in this encryption</li>
	 * <li>{@link Util#INT_BYTES} bytes - int - the previous {@link SymmetricKeyRatchet} counter, this is the counter before the last DH ratchet step</li>
	 * <li>{@link AsymmetricCryptography#getPublicKeySize()} bytes - byte[] - the public sender ratchet key</li>
	 * </ul>
	 * if {@link Settings#isUseUpdateAAD()} is {@code true} then:
	 * <ul>
	 * <li>{@link Settings#getMessageMacSize()} - byte[] - message mac</li>
	 * <li>{@link Util#INT_BYTES} bytes - int - length of the ciphertext</li>
	 * <li>length of ciphertext - byte[] - ciphertext</li>
	 * </ul>
	 *
	 * @param message to encrypt
	 * @return a header and the encrypted message (ciphertext)
	 * @throws NullPointerException if a session wasn't created earlier, to set the session decrypt a message with a registerMessage or create
	 * a new {@link Messenger} with a session specified
	 */
	public byte[] encryptMessage(byte[] message)
			throws IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException
	{
		//make sure a session exists
		if(session == null)
		{
			throw new NullPointerException(
					"Can't encrypt when there is no session! To create a session for this messenger decrypt a message with a registerMessage.");
		}
		
		//get all the variables
		byte[] senderRatchetKey = session.getRatchetKeyPair().getPublicKey();
		byte[] identityPublicKey = user.getIdentityPublicKey();
		byte[] hisIdentityKey = session.getRecipientIdentityKey();
		SymmetricKeyRatchet sendingRatchet = session.getSendingRatchet();
		//get the counter before the ratchet step
		byte[] counterBytes = sendingRatchet.getCounterBytes();
		
		//step the ratchet and get a new MessageKeys
		MessageKeys messageKeys = sendingRatchet.step();
		KeySpec messageKey = messageKeys.getMessageKey();
		IvSpec iv = messageKeys.getIV();
		byte[] ciphertext;
		byte[] messageMac = null;
		
		if(settings.isUseUpdateAAD())
		{
			//if we should use updateAAD specify it in encryption
			ciphertext = cipher.encrypt(messageKey, iv, message, identityPublicKey, hisIdentityKey, senderRatchetKey, counterBytes);
		} else
		{
			//if we don't use updateAAD create a new message mac
			ciphertext = cipher.encrypt(messageKey, iv, message);
			messageMac = createMac(messageKeys.getMacKey(), identityPublicKey, hisIdentityKey, senderRatchetKey, counterBytes, ciphertext);
		}
		
		//convert the result into a byte[]
		//get variables
		byte[] registerMessage = session.getRegisterMessage();
		byte[] previousSendingChainCounter = session.getPreviousSendingChainCounter();
		//convert length to int
		byte[] ciphertextLengthBytes = Util.intToBytes(ciphertext.length);
		boolean useHeaderEncryption = settings.isUseHeaderEncryption();
		byte[] hasRegisterMessage = Util.booleanToBytes(registerMessage != null);
		byte[] registerMessageLength = registerMessage == null ? null : Util.intToBytes(registerMessage.length);
		//if we use header encryption, encrypt the header
		if(useHeaderEncryption)
		{
			//combine the header into a single byte[]
			byte[] encryptedMessage = Util.combine(counterBytes, previousSendingChainCounter, senderRatchetKey, messageMac);
			//generate nonce for encryption
			byte[] headerEncryptionNonce = nonceGenerator.generateNonce();
			//encrypt the header
			byte[] encryptedHeader = cipher.encrypt(Util.newSymmetricKey(session.getSendingHeaderRatchet().getHeaderChainKey(), settings),
					Util.newIV(headerEncryptionNonce, settings),
					encryptedMessage);
			byte[] encryptedHeaderMac = null;
			//if we don't use updateAAD, add a mac so we can verify the ciphertext and nonce
			if(!settings.isUseUpdateAAD())
			{
				encryptedHeaderMac = createHeaderMac(session.getSendingHeaderRatchet().getAuthHeaderKey(), encryptedHeader, headerEncryptionNonce);
			}
			//combine all the variables needed for decryption
			return Util.combine(hasRegisterMessage,
					registerMessageLength,
					registerMessage,
					encryptedHeaderMac,
					headerEncryptionNonce,
					Util.intToBytes(encryptedHeader.length),
					encryptedHeader,
					Util.intToBytes(ciphertext.length),
					ciphertext);
		}
		//combine all the variables needed for decryption
		return Util.combine(hasRegisterMessage,
				registerMessageLength,
				registerMessage,
				counterBytes,
				previousSendingChainCounter,
				senderRatchetKey,
				messageMac,
				ciphertextLengthBytes,
				ciphertext);
	}
	
	/**
	 * Decrypts the specified message.
	 *
	 * @param message to decrypt
	 * @return the decrypted message (plaintext message)
	 */
	public byte[] decryptMessage(byte[] message)
			throws BadPaddingException, CounterTooLargeException, InvalidKeyException, IllegalBlockSizeException, MissingSkippedKeyException,
				   InvalidAlgorithmParameterException, MissingMatchingHeaderKeyException, TooManyDevicesException, VerificationFailedException
	{
		//decrypt message with a MessageReader
		return decryptMessage(new ByteArrayReader(message));
	}
	
	/**
	 * Decrypts a message using the specified blocking {@link Reader}.
	 *
	 * @param reader to read the message with
	 * @return the decrypted message (plaintext message)
	 */
	public byte[] decryptMessage(Reader reader)
			throws InvalidAlgorithmParameterException, CounterTooLargeException, IllegalBlockSizeException, BadPaddingException,
				   MissingSkippedKeyException, InvalidKeyException, MissingMatchingHeaderKeyException, TooManyDevicesException,
				   VerificationFailedException
	{
		//handle a registerMessage
		boolean hasRegisterMessage = reader.readBoolean();
		if(hasRegisterMessage)
		{
			int registerMessageLength = reader.readInt();
			byte[] registerMessage = reader.readBytes(registerMessageLength);
			updateSession(registerMessage);
		}
		if(settings.isUseHeaderEncryption())
		{
			byte[] encryptedHeaderMac = settings.isUseUpdateAAD() ? null : reader.readBytes(settings.getMessageMacSize());
			byte[] iv = reader.readBytes(settings.getIVSize());
			byte[] encryptedHeader = reader.readBytes(reader.readInt());
			byte[] ciphertext = reader.readBytes(reader.readInt());
			
			//decrypt with encrypted header
			return decryptWithEncryptedHeader(null, encryptedHeaderMac, iv, encryptedHeader, ciphertext);
		}
		//decrypt with normal decryption
		return decryptWithReader(reader, null);
	}
	
	/**
	 * Decrypts a message using the specified non-blocking {@link ConsumerReader}.
	 *
	 * @param reader to read the message with
	 * @param decryptionConsumer the consumer to be invoked with the decrypted message (plaintext message)
	 * @param exceptionCatcher the consumer to be invoked if an exception occurs
	 */
	public void decryptMessage(ConsumerReader reader, Consumer<byte[]> decryptionConsumer, Consumer<Throwable> exceptionCatcher)
	{
		reader.readBoolean(hasRegisterMessage ->
		{
			//handle a registerMessage
			if(hasRegisterMessage)
			{
				reader.readInt(registerMessageLength -> reader.readBytes(registerMessage ->
				{
					try
					{
						updateSession(registerMessage);
					} catch(InvalidKeyException | TooManyDevicesException e)
					{
						exceptionCatcher.accept(e);
						return;
					}
					continueDecryptMessage(reader, decryptionConsumer, exceptionCatcher);
				}, registerMessageLength));
			} else
			{
				continueDecryptMessage(reader, decryptionConsumer, exceptionCatcher);
			}
		});
	}
	
	/**
	 * A continuation of {@link #decryptMessage(ConsumerReader, Consumer, Consumer)}, this is for after a register message (if specified) has been
	 * processed.
	 *
	 * @param reader to read the message with
	 * @param decryptionConsumer the consumer to be invoked with the decrypted message (plaintext message)
	 * @param exceptionCatcher the consumer to be invoked if an exception occurs
	 */
	private void continueDecryptMessage(ConsumerReader reader, Consumer<byte[]> decryptionConsumer, Consumer<Throwable> exceptionCatcher)
	{
		//continue decryption
		if(settings.isUseHeaderEncryption())
		{
			Consumer<byte[]> next = encryptedHeaderMac -> reader.readBytes(iv -> reader.readInt(headerLength -> reader.readBytes(encryptedHeader -> reader
					.readInt(ciphertextLength -> reader.readBytes(ciphertext ->
					{
						try
						{
							decryptionConsumer.accept(decryptWithEncryptedHeader(null, encryptedHeaderMac, iv, encryptedHeader, ciphertext));
						} catch(MissingMatchingHeaderKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | MissingSkippedKeyException | CounterTooLargeException | TooManyDevicesException | VerificationFailedException e)
						{
							exceptionCatcher.accept(e);
						}
					}, ciphertextLength)), headerLength)), settings.getIVSize());
			if(settings.isUseUpdateAAD())
			{
				next.accept(null);
				return;
			}
			reader.readBytes(next, settings.getMessageMacSize());
		} else
		{
			reader.readInt(receivedCounter -> reader.readInt(previousSendingChainCounter -> reader.readBytes(receivedRatchetKey ->
			{
				Consumer<byte[]> next = messageMac -> reader.readInt(ciphertextLength -> reader.readBytes(ciphertext ->
				{
					try
					{
						decryptionConsumer.accept(decryptMessage(null,
								receivedCounter,
								previousSendingChainCounter,
								receivedRatchetKey,
								messageMac,
								ciphertext));
					} catch(InvalidKeyException | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException | CounterTooLargeException | MissingSkippedKeyException | TooManyDevicesException | VerificationFailedException e)
					{
						exceptionCatcher.accept(e);
					}
				}, ciphertextLength));
				if(!settings.isUseUpdateAAD())
				{
					reader.readBytes(next, settings.getMessageMacSize());
					return;
				}
				next.accept(null);
			}, settings.getAsymmetricCryptography().getPublicKeySize())));
		}
	}
	
	/**
	 * /**
	 * Decrypts a message using the specified blocking {@link Reader}.
	 *
	 * @param reader to read the message with
	 * @param messageKeys to decrypt the message with, should be {@code null} if no skipped key was found
	 * @return the decrypted message (plaintext message)
	 */
	private byte[] decryptWithReader(Reader reader, MessageKeys messageKeys)
			throws InvalidAlgorithmParameterException, CounterTooLargeException, IllegalBlockSizeException, BadPaddingException,
				   MissingSkippedKeyException, InvalidKeyException, TooManyDevicesException, VerificationFailedException
	{
		int receivedCounter = reader.readInt();
		int previousSendingChainCounter = reader.readInt();
		byte[] receivedRatchetKey = reader.readBytes(settings.getAsymmetricCryptography().getPublicKeySize());
		byte[] messageMac = null;
		if(!settings.isUseUpdateAAD())
		{
			messageMac = reader.readBytes(settings.getMessageMacSize());
		}
		int ciphertextLength = reader.readInt();
		byte[] ciphertext = reader.readBytes(ciphertextLength);
		if(messageKeys == null)
		{
			return decryptMessage(null, receivedCounter, previousSendingChainCounter, receivedRatchetKey, messageMac, ciphertext);
		}
		return decryptMessage(messageKeys, receivedCounter, receivedRatchetKey, messageMac, ciphertext);
	}
	
	/**
	 * Decrypts the specified message.
	 *
	 * @param registerMessage is the register details, possibly {@code null}
	 * @param encryptedHeaderMac is used to verify the specified encryptedHeader and specified iv, should be {@code null} if
	 * {@link Settings#isUseUpdateAAD()} is {@code true}
	 * @param iv which was used to encrypt the specified encryptedHeader
	 * @param encryptedHeader is the encrypted version of the header containing required information to decrypt the specified ciphertext
	 * @param ciphertext to decrypt
	 * @return the decrypted message (plaintext message)
	 */
	public byte[] decryptWithEncryptedHeader(byte[] registerMessage, byte[] encryptedHeaderMac, byte[] iv, byte[] encryptedHeader, byte[] ciphertext)
			throws MissingMatchingHeaderKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException,
				   InvalidKeyException, MissingSkippedKeyException, CounterTooLargeException, TooManyDevicesException, VerificationFailedException
	{
		updateSession(registerMessage);
		IvSpec ivObject = Util.newIV(iv, settings);
		boolean validateMac = !settings.isUseUpdateAAD();
		byte[] decryptedHeader = null;
		//try to see if there is a match in skipped keys
		SkippedKeysStorage skippedKeysStorage = session.getSkippedKeysStorage();
		MessageKeys messageKeys = null;
		synchronized(skippedKeysStorage.getLock())
		{
			Iterator<SkippedKey> skippedKeys = skippedKeysStorage.getSkippedKeys().iterator();
			while(skippedKeys.hasNext())
			{
				SkippedKey skippedKey = skippedKeys.next();
				KeySpec headerKey = Util.newSymmetricKey(skippedKey.getKey(), settings);
				if(validateMac)
				{
					if(!verifyHeaderMac(skippedKey.getAuthKey(), encryptedHeader, iv, encryptedHeaderMac))
					{
						continue;
					}
				}
				try
				{
					decryptedHeader = cipher.decrypt(headerKey, ivObject, encryptedHeader);
				} catch(BadPaddingException ignored)
				{
					continue;
				}
				//make sure the counter matches
				int counter = Util.bytesToInt(decryptedHeader);
				if(counter != skippedKey.getCounter())
				{
					decryptedHeader = null;
					continue;
				}
				messageKeys = skippedKey.cancelThenGetMessageKeys();
				skippedKeys.remove();
				break;
			}
		}
		if(messageKeys == null)
		{
			//if there wasn't a skipped key then try to see if it's any of the current ratchets
			HeaderKeyRatchet receivingHeaderRatchet = session.getReceivingHeaderRatchet();
			byte[] headerReceivingChainKeyBytes = receivingHeaderRatchet.getHeaderChainKey();
			byte[] nextHeaderReceivingChainKeyBytes = receivingHeaderRatchet.getNextHeaderChainKey();
			KeySpec headerReceivingChainKey = headerReceivingChainKeyBytes == null ? null : Util.newSymmetricKey(headerReceivingChainKeyBytes,
					settings);
			KeySpec nextHeaderReceivingChainKey = nextHeaderReceivingChainKeyBytes == null ? null : Util.newSymmetricKey(
					nextHeaderReceivingChainKeyBytes,
					settings);
			if(validateMac)
			{
				//if we validate mac then verify and set it
				if(headerReceivingChainKey != null && verifyHeaderMac(receivingHeaderRatchet.getAuthHeaderKey(),
						encryptedHeader,
						iv,
						encryptedHeaderMac))
				{
					decryptedHeader = cipher.decrypt(headerReceivingChainKey, ivObject, encryptedHeader);
				} else if(nextHeaderReceivingChainKey != null && verifyHeaderMac(receivingHeaderRatchet.getNextAuthHeaderKey(),
						encryptedHeader,
						iv,
						encryptedHeaderMac))
				{
					decryptedHeader = cipher.decrypt(nextHeaderReceivingChainKey, ivObject, encryptedHeader);
				}
			} else
			{
				//if we don't validate mac then try to decrypt and a BadPaddingException will be thrown if verification has failed
				if(headerReceivingChainKey != null)
				{
					try
					{
						decryptedHeader = cipher.decrypt(headerReceivingChainKey, ivObject, encryptedHeader);
					} catch(BadPaddingException ignored)
					{
					}
				}
				if(decryptedHeader == null && nextHeaderReceivingChainKey != null)
				{
					try
					{
						decryptedHeader = cipher.decrypt(nextHeaderReceivingChainKey, ivObject, encryptedHeader);
					} catch(BadPaddingException ignored)
					{
					}
				}
			}
		} else
		{
			//flush after, outside of the lock
			skippedKeysStorage.flush();
		}
		//if we still don't have a decryptedHeader we notify the caller it's missing
		if(decryptedHeader == null)
		{
			throw new MissingMatchingHeaderKeyException();
		}
		return decryptWithReader(new ByteArrayReader(Util.combine(decryptedHeader, Util.intToBytes(ciphertext.length), ciphertext)), messageKeys);
	}
	
	/**
	 * Decrypts the specified message.
	 *
	 * @param registerMessage is the register details, possibly {@code null}
	 * @param receivedCounter is the sender's counter of the symmetric ratchet before the {@link MessageKeys} used to encrypt the specified ciphertext
	 * were generated
	 * @param previousRatchetCounter is the sender's counter of the symmetric ratchet before the last DH ratchet step, if a DH ratchet step has yet to occur
	 * this will be {@code 0}
	 * @param receivedRatchetKey is the sender's ratchet public key of the current ratchet key pair
	 * @param messageMac is the mac of the message, {@code null} if {@link Settings#isUseUpdateAAD()} is {@code true}
	 * @param ciphertext to decrypt
	 * @return the decrypted message (plaintext message)
	 */
	public byte[] decryptMessage(byte[] registerMessage,
								 int receivedCounter,
								 int previousRatchetCounter,
								 byte[] receivedRatchetKey,
								 byte[] messageMac,
								 byte[] ciphertext)
			throws InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, CounterTooLargeException,
				   MissingSkippedKeyException, TooManyDevicesException, VerificationFailedException
	{
		updateSession(registerMessage);
		SkippedKeysStorage skippedKeyStorage = session.getSkippedKeysStorage();
		SymmetricKeyRatchet receivingRatchet = session.getReceivingRatchet();
		byte[] currentReceivedRatchetKey = session.getReceivedRatchetKey();
		if(skippedKeyStorage != null)
		{
			//see if a message key can be found, if yes decrypt with it
			MessageKeys messageKeys = skippedKeyStorage.getSkippedMessageKeys(receivedRatchetKey, receivedCounter);
			if(messageKeys != null)
			{
				return decryptMessage(messageKeys, receivedCounter, receivedRatchetKey, messageMac, ciphertext);
			}
		}
		//if we use header encryption then we should use time-constant comparison, else we should use normal equals
		//we need a DH ratchet step if the ratchet keys don't match
		boolean needDHRatchetStep = !(settings.isUseHeaderEncryption()
									  ? MessageDigest.isEqual(currentReceivedRatchetKey, receivedRatchetKey)
									  : Arrays.equals(currentReceivedRatchetKey, receivedRatchetKey));
		int myCounter;
		if(!needDHRatchetStep && (myCounter = receivingRatchet.getCounter()) > receivedCounter)
		{
			throw new MissingSkippedKeyException("Missing skipped key! Current counter: " + myCounter + ", received counter " + receivedCounter);
		}
		//perform DH ratchet step
		if(needDHRatchetStep)
		{
			//skip all keys from the previous ratchet key
			skipKeys(session, previousRatchetCounter, receivedRatchetKey, settings);
			session.dhStep(receivedRatchetKey);
			session.setRegisterMessage(null);
		}
		//skip keys in the ratchet
		skipKeys(session, receivedCounter, receivedRatchetKey, settings);
		//step then decrypt
		MessageKeys messageKeys = receivingRatchet.step();
		return decryptMessage(messageKeys, receivedCounter, receivedRatchetKey, messageMac, ciphertext);
	}
	
	/**
	 * Decrypts the specified message.
	 *
	 * @param messageKeys to decrypt the message with
	 * @param receivedCounter is the sender's counter of the symmetric ratchet before the {@link MessageKeys} used to encrypt the specified ciphertext
	 * were generated
	 * @param receivedRatchetKey is the sender's ratchet public key of the current ratchet key pair
	 * @param messageMac is the mac of the message, {@code null} if {@link Settings#isUseUpdateAAD()} is {@code true}
	 * @param ciphertext to decrypt
	 * @return the decrypted message (plaintext message)
	 */
	private byte[] decryptMessage(MessageKeys messageKeys, int receivedCounter, byte[] receivedRatchetKey, byte[] messageMac, byte[] ciphertext)
			throws IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException,
				   VerificationFailedException
	{
		KeySpec messageKey = messageKeys.getMessageKey();
		IvSpec iv = messageKeys.getIV();
		byte[] hisIdentityKey = session.getRecipientIdentityKey();
		byte[] identityPublicKey = user.getIdentityPublicKey();
		byte[] counterBytes = Util.intToBytes(receivedCounter);
		byte[] decryptedMessage;
		if(settings.isUseUpdateAAD())
		{
			//if we use updateAAD decrypt with additional authentication data
			try
			{
				decryptedMessage = cipher.decrypt(messageKey, iv, ciphertext, hisIdentityKey, identityPublicKey, receivedRatchetKey, counterBytes);
			} catch(AEADBadTagException cause)
			{
				throw new VerificationFailedException("Failed to verify message!", cause);
			}
		} else
		{
			//authenticate (verify) mac
			if(!verifyMac(messageKeys.getMacKey(), hisIdentityKey, identityPublicKey, receivedRatchetKey, counterBytes, ciphertext, messageMac))
			{
				throw new VerificationFailedException("Failed to verify message MAC!");
			}
			decryptedMessage = cipher.decrypt(messageKey, iv, ciphertext);
		}
		return decryptedMessage;
	}
	
	/**
	 * Skips keys in the specified session's receiving ratchet until the receiving ratchet {@link SymmetricKeyRatchet#getCounter()} equals
	 * the specified receivedCounter.
	 *
	 * @param session who's keys need to be skipped
	 * @param receivedCounter to skip to
	 * @param receivedRatchetKey is the sender's ratchet public key of the current ratchet key pair, will be the key identifier if
	 * {@link Settings#isUseHeaderEncryption()} is {@code false}
	 * @param settings to skip keys with
	 * @throws IllegalArgumentException if the specified receivedCounter is bigger than the current counter and
	 * {@link Session#getSkippedKeysStorage()} returns {@code null}
	 * @throws CounterTooLargeException if the difference between the specified receivedCounter and the current counter is bigger than
	 * {@link Settings#getMaxSkipKeys()}
	 */
	private void skipKeys(Session session, int receivedCounter, byte[] receivedRatchetKey, Settings settings)
			throws CounterTooLargeException, InvalidKeyException
	{
		SymmetricKeyRatchet receivingRatchet = session.getReceivingRatchet();
		byte[] receivingChainKey = receivingRatchet.getChainKey();
		//ensure we have a receivingChainKey to even perform skip on
		if(receivingChainKey != null)
		{
			int myCounter = receivingRatchet.getCounter();
			SkippedKeysStorage skippedKeysStorage = session.getSkippedKeysStorage();
			if(SkippedKeysStorage.ensureCanSkip(skippedKeysStorage, myCounter, receivedCounter, settings))
			{
				return;
			}
			//if we use header encryption the key should be the header receiving chain key, else it should be the received ratchet key
			byte[] key = settings.isUseHeaderEncryption() ? session.getReceivingHeaderRatchet().getHeaderChainKey() : receivedRatchetKey;
			byte[] authKey = session.getReceivingHeaderRatchet().getAuthHeaderKey();
			while(myCounter < receivedCounter)
			{
				MessageKeys messageKeys = receivingRatchet.step();
				skippedKeysStorage.addSkippedKey(key, authKey, myCounter, messageKeys);
				myCounter++;
			}
			skippedKeysStorage.flush();
		}
	}
	
	private void updateSession(byte[] registerMessage) throws InvalidKeyException, TooManyDevicesException
	{
		if(session == null)
		{
			if(registerMessage == null)
			{
				throw new IllegalArgumentException("Missing registerMessage in the message!");
			}
			session = user.bobRegister(userDeviceUID, registerMessage);
		}
	}
	
	/**
	 * Creates a mac using the specified parameters.
	 *
	 * @param macKey to create mac with
	 * @param senderIdentityKey is the sender's public identity key
	 * @param receiverIdentityKey is the receiver's public identity key
	 * @param senderRatchetKey is the sender's public ratchet key
	 * @param counter is the counter of the mac
	 * @param ciphertext is the ciphertext of the mac
	 * @return a mac based on the specified parameters
	 */
	private byte[] createMac(KeySpec macKey,
							 byte[] senderIdentityKey,
							 byte[] receiverIdentityKey,
							 byte[] senderRatchetKey,
							 byte[] counter,
							 byte[] ciphertext) throws InvalidKeyException
	{
		mac.init(macKey);
		mac.update(senderIdentityKey);
		mac.update(receiverIdentityKey);
		mac.update(senderRatchetKey);
		mac.update(counter);
		mac.update(ciphertext);
		return returnOrRange(mac.doFinal(), settings);
	}
	
	/**
	 * Verifies the specified otherMac based on the specified parameters.
	 *
	 * @param macKey to create mac with
	 * @param senderIdentityKey is the sender's public identity key
	 * @param receiverIdentityKey is the receiver's public identity key
	 * @param senderRatchetKey is the sender's public ratchet key
	 * @param counter is the counter of the mac
	 * @param ciphertext is the ciphertext of the mac
	 * @param otherMac to verify
	 * @return whether the mac matches
	 */
	private boolean verifyMac(KeySpec macKey,
							  byte[] senderIdentityKey,
							  byte[] receiverIdentityKey,
							  byte[] senderRatchetKey,
							  byte[] counter,
							  byte[] ciphertext,
							  byte[] otherMac) throws InvalidKeyException
	{
		return MessageDigest.isEqual(createMac(macKey, senderIdentityKey, receiverIdentityKey, senderRatchetKey, counter, ciphertext), otherMac);
	}
	
	/**
	 * Creates a header mac using the specified parameters.
	 *
	 * @param macKey to create mac with
	 * @param ciphertext is the ciphertext of the mac
	 * @param iv is the iv of the mac
	 * @return a mac based on the specified parameters
	 */
	private byte[] createHeaderMac(byte[] macKey, byte[] ciphertext, byte[] iv) throws InvalidKeyException
	{
		mac.init(Util.newMacKey(macKey, settings));
		mac.update(ciphertext);
		mac.update(iv);
		return returnOrRange(mac.doFinal(), settings);
	}
	
	/**
	 * Verifies the specified otherMac based on the specified parameters.
	 *
	 * @param macKey to create mac with
	 * @param ciphertext is the ciphertext of the mac
	 * @param iv is the iv of the mac
	 * @param otherMac to verify
	 * @return whether the mac matches
	 */
	private boolean verifyHeaderMac(byte[] macKey, byte[] ciphertext, byte[] iv, byte[] otherMac) throws InvalidKeyException
	{
		return MessageDigest.isEqual(createHeaderMac(macKey, ciphertext, iv), otherMac);
	}
	
	/**
	 * @param bytes to return or range
	 * @param settings to use
	 * @return if the specified bytes length is {@link Settings#getMessageMacSize()} then the specified bytes is returned, else returns a range
	 * of the bytes from 0 to {@link Settings#getMessageMacSize()}
	 */
	private static byte[] returnOrRange(byte[] bytes, Settings settings)
	{
		int targetLength = settings.getMessageMacSize();
		if(bytes.length == targetLength)
		{
			return bytes;
		}
		return Util.range(bytes, 0, targetLength);
	}
}