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
package oughttoprevail.prevailprotocol.session;

import java.security.InvalidKeyException;

import oughttoprevail.prevailprotocol.User;
import oughttoprevail.prevailprotocol.doubleratchet.DHRatchet;
import oughttoprevail.prevailprotocol.doubleratchet.HeaderKeyRatchet;
import oughttoprevail.prevailprotocol.doubleratchet.SymmetricKeyRatchet;
import oughttoprevail.prevailprotocol.kdf.KDF;
import oughttoprevail.prevailprotocol.kdf.SimpleKDF;
import oughttoprevail.prevailprotocol.keys.KeyPair;
import oughttoprevail.prevailprotocol.messenger.Messenger;
import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.Directory;
import oughttoprevail.prevailprotocol.storage.SkippedKeysStorage;
import oughttoprevail.prevailprotocol.storage.Storage;
import oughttoprevail.prevailprotocol.storage.fields.Field;
import oughttoprevail.prevailprotocol.storage.fields.JavaSerDes;
import oughttoprevail.prevailprotocol.uid.UserDeviceUID;
import oughttoprevail.prevailprotocol.util.Util;

/**
 * A {@link Session} is mostly just an information holder for {@link Messenger}.
 */
public class Session
{
	/**
	 * Session storage name
	 */
	private static final String SESSION_STORAGE = "Session";
	
	/**
	 * Device directory for the session to be stored in
	 */
	private final Directory deviceDirectory;
	/**
	 * User who created this session
	 */
	private final User user;
	/**
	 * Whether to create a {@link SkippedKeysStorage}
	 */
	private final boolean storeSkippedStorage;
	/**
	 * Storage of this session
	 */
	private final Storage storage;
	/**
	 * The recipient identity public key
	 */
	private final Field<byte[]> recipientIdentityKey;
	/**
	 * The current {@link oughttoprevail.prevailprotocol.doubleratchet.DHRatchet} key pair
	 */
	private final Field<KeyPair> ratchetKeyPair;
	/**
	 * The current root key
	 */
	private final Field<byte[]> rootKey;
	/**
	 * The current received (remote) ratchet public key (received from the recipient user)
	 */
	private final Field<byte[]> receivedRatchetKey;
	/**
	 * The previous sending {@link oughttoprevail.prevailprotocol.doubleratchet.SymmetricKeyRatchet} counter
	 */
	private final Field<byte[]> previousSendingChainCounter;
	/**
	 * The current register message
	 */
	private final Field<byte[]> registerMessage;
	/**
	 * Storage for skipped keys, or {@code null} if {@link #storeSkippedStorage} is {@code false}.
	 */
	private SkippedKeysStorage skippedKeysStorage;
	/**
	 * For {@link SymmetricKeyRatchet}
	 */
	private final KDF kdf;
	/**
	 * For {@link SymmetricKeyRatchet}
	 */
	private final SimpleKDF simpleKDF;
	/**
	 * Settings to use
	 */
	private final Settings settings;
	/**
	 * The recipient user device, who this session is for (if the conversation was Alice and Bob and {@link #user} was Alice then this would be Bob)
	 */
	private final UserDeviceUID recipientUserDeviceUID;
	private DHRatchet dhRatchet;
	private SymmetricKeyRatchet sendingRatchet;
	private SymmetricKeyRatchet receivingRatchet;
	private HeaderKeyRatchet sendingHeaderRatchet;
	private HeaderKeyRatchet receivingHeaderRatchet;
	/**
	 * Messenger to encrypt and decrypt messages with
	 */
	private Messenger messenger;
	
	/**
	 * Constructs a new {@link Session}.
	 *
	 * @param loadedSession whether this session is a loaded session or a new session
	 */
	public Session(Directory userDirectory,
				   User user,
				   boolean storeSkippedStorage,
				   KDF kdf,
				   SimpleKDF simpleKDF,
				   UserDeviceUID recipientUserDeviceUID,
				   boolean loadedSession,
				   Settings settings)
	{
		this.user = user;
		this.storeSkippedStorage = storeSkippedStorage;
		deviceDirectory = userDirectory.directory(recipientUserDeviceUID.getDeviceId().toString());
		storage = deviceDirectory.storage(SESSION_STORAGE);
		recipientIdentityKey = storage.getField(JavaSerDes.BYTE_ARRAY_SER_DES);
		ratchetKeyPair = storage.getField(KeyPair.SER_DES);
		rootKey = storage.getField(JavaSerDes.BYTE_ARRAY_SER_DES);
		receivedRatchetKey = storage.getField(JavaSerDes.BYTE_ARRAY_SER_DES);
		previousSendingChainCounter = storage.getField(JavaSerDes.BYTE_ARRAY_SER_DES);
		registerMessage = storage.getField(JavaSerDes.BYTE_ARRAY_SER_DES);
		this.kdf = kdf;
		this.simpleKDF = simpleKDF;
		this.settings = settings;
		this.recipientUserDeviceUID = recipientUserDeviceUID;
		if(loadedSession)
		{
			initDoubleRatchetNSkip();
		}
	}
	
	/**
	 * After keys have been agreed this should be invoked with all of them to save.
	 *
	 * @param recipientIdentityKey the recipient's public identity key
	 * @param ratchetKeyPair my current ratchet key pair
	 * @param rootKey my current root key
	 * @param receivedRatchetKey the recipient's current ratchet public key
	 * @param sendingChainKey my sending ratchet chain key
	 * @param receivingChainKey my receiving ratchet chain key
	 * @param sendingHeaderChainKey my sending header ratchet chain key
	 * @param authSendingHeaderChainKey authentication key for the specified sendingHeaderChainKey
	 * @param nextSendingHeaderChainKey my next sending ratchet chain key
	 * @param nextAuthSendingHeaderChainKey authentication key for the specified nextSendingHeaderChainKey
	 * @param nextReceivingHeaderChainKey my next receiving ratchet chain key
	 * @param nextAuthReceivingHeaderChainKey authentication key for the specified nextReceivingHeaderChainKey
	 */
	public void keyAgreement(byte[] recipientIdentityKey,
							 KeyPair ratchetKeyPair,
							 byte[] rootKey,
							 byte[] receivedRatchetKey,
							 byte[] sendingChainKey,
							 byte[] receivingChainKey,
							 byte[] sendingHeaderChainKey,
							 byte[] authSendingHeaderChainKey,
							 byte[] nextSendingHeaderChainKey,
							 byte[] nextAuthSendingHeaderChainKey,
							 byte[] nextReceivingHeaderChainKey,
							 byte[] nextAuthReceivingHeaderChainKey)
	{
		this.recipientIdentityKey.set(recipientIdentityKey);
		this.ratchetKeyPair.set(ratchetKeyPair);
		this.rootKey.set(rootKey);
		this.receivedRatchetKey.set(receivedRatchetKey);
		this.previousSendingChainCounter.set(Util.intToBytes(0));
		initDoubleRatchetNSkip();
		sendingRatchet.chainKeyChanged(sendingChainKey);
		receivingRatchet.chainKeyChanged(receivingChainKey);
		sendingHeaderRatchet.init(sendingHeaderChainKey, authSendingHeaderChainKey, nextSendingHeaderChainKey, nextAuthSendingHeaderChainKey);
		receivingHeaderRatchet.init(null, null, nextReceivingHeaderChainKey, nextAuthReceivingHeaderChainKey);
		storage.flush();
	}
	
	/**
	 * Initializes ratchet related variables and the skipped storage.
	 */
	private void initDoubleRatchetNSkip()
	{
		dhRatchet = new DHRatchet(this, settings);
		sendingRatchet = new SymmetricKeyRatchet(kdf, simpleKDF, storage, settings)
		{
			@Override
			public void chainKeyChanged(byte[] chainKey)
			{
				byte[] counter = getCounterBytes();
				previousSendingChainCounter.set(counter);
				super.chainKeyChanged(chainKey);
			}
		};
		receivingRatchet = new SymmetricKeyRatchet(kdf, simpleKDF, storage, settings);
		sendingHeaderRatchet = new HeaderKeyRatchet(storage);
		receivingHeaderRatchet = new HeaderKeyRatchet(storage);
		messenger = new Messenger(user, this, settings);
		if(storeSkippedStorage)
		{
			this.skippedKeysStorage = new SkippedKeysStorage(deviceDirectory, settings);
		}
	}
	
	/**
	 * Performs a {@link DHRatchet} step with the specified receivedRatchetKey
	 *
	 * @param receivedRatchetKey is the current recipient's ratchet public key
	 */
	public void dhStep(byte[] receivedRatchetKey) throws InvalidKeyException
	{
		dhRatchet.step(receivedRatchetKey);
		storage.flush();
	}
	
	/**
	 * Updates {@link DHRatchet} related variables
	 *
	 * @param receivedRatchetKey used in the {@link DHRatchet} step
	 */
	public void dhRatchetChange(byte[] receivedRatchetKey)
	{
		this.receivedRatchetKey.set(receivedRatchetKey);
		//update the value to the current value so if the storage is change base it will know a change occurred
		this.rootKey.set(rootKey.get());
		storage.flush();
	}
	
	/**
	 * Deletes all data of this session
	 */
	void deleteSession()
	{
		deviceDirectory.delete();
	}
	
	public KDF getKDF()
	{
		return kdf;
	}
	
	public SkippedKeysStorage getSkippedKeysStorage()
	{
		return skippedKeysStorage;
	}
	
	public SymmetricKeyRatchet getSendingRatchet()
	{
		return sendingRatchet;
	}
	
	public SymmetricKeyRatchet getReceivingRatchet()
	{
		return receivingRatchet;
	}
	
	public HeaderKeyRatchet getSendingHeaderRatchet()
	{
		return sendingHeaderRatchet;
	}
	
	public HeaderKeyRatchet getReceivingHeaderRatchet()
	{
		return receivingHeaderRatchet;
	}
	
	public UserDeviceUID getRecipientUserDeviceUID()
	{
		return recipientUserDeviceUID;
	}
	
	public byte[] getRecipientIdentityKey()
	{
		return recipientIdentityKey.get();
	}
	
	/**
	 * Sets the current ratchet key pair to the specified ratchetKeyPair.
	 *
	 * @param ratchetKeyPair to be the new ratchet key pair
	 */
	public void setRatchetKeyPair(KeyPair ratchetKeyPair)
	{
		this.ratchetKeyPair.set(ratchetKeyPair);
	}
	
	public KeyPair getRatchetKeyPair()
	{
		return ratchetKeyPair.get();
	}
	
	public byte[] getRootKey()
	{
		return rootKey.get();
	}
	
	public byte[] getReceivedRatchetKey()
	{
		return receivedRatchetKey.get();
	}
	
	public byte[] getPreviousSendingChainCounter()
	{
		return previousSendingChainCounter.get();
	}
	
	/**
	 * Sets the specified registerMessage if it and {@link #getRegisterMessage()} aren't {@code null}.
	 *
	 * @param registerMessage to be to the new register message
	 */
	public void setRegisterMessage(byte[] registerMessage)
	{
		if(registerMessage == null && getRegisterMessage() == null)
		{
			return;
		}
		this.registerMessage.set(registerMessage);
		storage.flush();
	}
	
	public byte[] getRegisterMessage()
	{
		return registerMessage.get();
	}
	
	public Messenger getMessenger()
	{
		return messenger;
	}
}