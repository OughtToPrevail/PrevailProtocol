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
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import oughttoprevail.prevailprotocol.User;
import oughttoprevail.prevailprotocol.doubleratchet.SymmetricKeyRatchet;
import oughttoprevail.prevailprotocol.kdf.KDF;
import oughttoprevail.prevailprotocol.kdf.SimpleKDF;
import oughttoprevail.prevailprotocol.keys.KeyPair;
import oughttoprevail.prevailprotocol.messenger.EncryptedMessage;
import oughttoprevail.prevailprotocol.session.Session;
import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.Directory;
import oughttoprevail.prevailprotocol.storage.SkippedKeysStorage;
import oughttoprevail.prevailprotocol.storage.Storage;
import oughttoprevail.prevailprotocol.storage.fields.Field;
import oughttoprevail.prevailprotocol.storage.fields.JavaSerDes;
import oughttoprevail.prevailprotocol.uid.RecipientUser;
import oughttoprevail.prevailprotocol.uid.UID;
import oughttoprevail.prevailprotocol.uid.UserDeviceUID;
import oughttoprevail.prevailprotocol.util.Util;

/**
 * A session for a {@link Group}.
 */
class GroupSession
{
	/**
	 * Group session storage name
	 */
	private static final String GROUP_SESSION_STORAGE = "GroupSession";
	
	/**
	 * User who created this session
	 */
	private final User user;
	/**
	 * Directory of this session
	 */
	private final Directory directory;
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
	 * Sending ratchet to use for {@link oughttoprevail.prevailprotocol.messenger.MessageKeys} derivation
	 */
	private final SymmetricKeyRatchet sendingRatchet;
	/**
	 * Signature key pair, signature keys pair is used by other users to verify we are who we say we are
	 */
	private final Field<KeyPair> signatureKeyPair;
	/**
	 * When this session expires (when a session expires it should be removed).
	 * Session expiration starts when a member has left
	 */
	private final Field<Long> expirationDate;
	/**
	 * Map from {@link UserDeviceUID} (user and device identifiers) to {@link SignatureNRatchet}
	 */
	private final Map<UserDeviceUID, SignatureNRatchet> receivingRatchets;
	/**
	 * Messenger of this session
	 */
	private final GroupMessenger messenger;
	
	/**
	 * Constructs a new {@link GroupSession}.
	 *
	 * @param user who created this session
	 * @param kdf for {@link SymmetricKeyRatchet}
	 * @param simpleKDF for {@link SymmetricKeyRatchet}
	 * @param sessionDirectory this session's personal directory
	 * @param skippedKeysStorage to store skipped keys in
	 * @param members list of members
	 * @param settings to use
	 */
	GroupSession(User user,
				 KDF kdf,
				 SimpleKDF simpleKDF,
				 Directory sessionDirectory,
				 SkippedKeysStorage skippedKeysStorage,
				 List<RecipientUser> members,
				 Settings settings)
	{
		this.user = user;
		this.kdf = kdf;
		this.simpleKDF = simpleKDF;
		this.settings = settings;
		this.directory = sessionDirectory;
		Storage storage = directory.storage(GROUP_SESSION_STORAGE);
		this.sendingRatchet = new SymmetricKeyRatchet(kdf, simpleKDF, storage, settings);
		this.signatureKeyPair = storage.getField(KeyPair.SER_DES);
		this.expirationDate = storage.getField(JavaSerDes.LONG_SER_DES);
		this.receivingRatchets = new HashMap<>();
		this.messenger = new GroupMessenger(user, this, skippedKeysStorage, settings);
		if(signatureKeyPair.get() == null)
		{
			signatureKeyPair.set(settings.getAsymmetricCryptography().generateKeyPair());
			sendingRatchet.chainKeyChanged(settings.getRandom().nextBytes(settings.getSymmetricKeySize()));
			storage.flush();
		}
		for(RecipientUser member : members)
		{
			UID userId = member.getUserId();
			Directory memberDirectory = directory.directory(userId.toString());
			for(UID deviceId : member.getDeviceIds())
			{
				Storage deviceStorage = memberDirectory.storage(deviceId.toString());
				receivingRatchets.put(new UserDeviceUID(userId, deviceId),
						new SignatureNRatchet(new SymmetricKeyRatchet(kdf, simpleKDF, deviceStorage, settings), null, deviceStorage));
			}
		}
	}
	
	/**
	 * Joins the specified userDeviceUID with the specified senderKey to the session.
	 *
	 * @param userDeviceUID of the member who is joining
	 * @param senderKey of the member who is joining
	 */
	void memberJoined(UserDeviceUID userDeviceUID, byte[] senderKey)
	{
		byte[][] keys = Util.splitLengths(senderKey, settings.getSymmetricKeySize(), settings.getAsymmetricCryptography().getPublicKeySize());
		byte[] signatureKey = keys[0];
		byte[] chainKey = keys[1];
		Storage storage = directory.directory(userDeviceUID.getUserId().toString()).storage(userDeviceUID.getDeviceId().toString());
		SignatureNRatchet signatureNRatchet = new SignatureNRatchet(new SymmetricKeyRatchet(kdf, simpleKDF, storage, settings),
				signatureKey,
				storage);
		receivingRatchets.put(userDeviceUID, signatureNRatchet);
		signatureNRatchet.getReceivingRatchet().chainKeyChanged(chainKey);
		storage.flush();
	}
	
	/**
	 * Leaves the specified userDeviceUID from this session.
	 *
	 * @param userDeviceUID who is leaving
	 * @return whether he was actually in the session ({@code true} if he was or {@code false} if he wasn't)
	 */
	boolean memberLeft(UserDeviceUID userDeviceUID)
	{
		return receivingRatchets.remove(userDeviceUID) != null;
	}
	
	/**
	 * Encrypts the sender key to all current known members.
	 *
	 * @return an array of encrypted sender key (each with it's destination)
	 */
	EncryptedMessage[] encryptSenderKeyToAll()
			throws InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException
	{
		byte[] senderKey = createSenderKey();
		EncryptedMessage[] messages = new EncryptedMessage[receivingRatchets.size()];
		int index = 0;
		for(UserDeviceUID identifier : receivingRatchets.keySet())
		{
			Session session = user.getSession(identifier);
			if(session == null)
			{
				throw new IllegalStateException(identifier + " session's is missing!");
			}
			messages[index++] = new EncryptedMessage(identifier, session.getMessenger().encryptMessage(senderKey));
		}
		return messages;
	}
	
	/**
	 * @return the messenger of this session
	 */
	GroupMessenger getMessenger()
	{
		return messenger;
	}
	
	/**
	 * @return the sender key
	 */
	byte[] createSenderKey()
	{
		return Util.combine(signatureKeyPair.get().getPublicKey(), sendingRatchet.getChainKey());
	}
	
	/**
	 * @param userDeviceUID to get {@link SignatureNRatchet} for
	 * @return the {@link SignatureNRatchet} for the specified userDeviceUID or {@code null} if there isn't one
	 */
	SignatureNRatchet getSignatureNRatchet(UserDeviceUID userDeviceUID)
	{
		return receivingRatchets.get(userDeviceUID);
	}
	
	/**
	 * Sets the expirationDate to the specified expirationDate.
	 * <b>NOTE: {@link GroupSession} is not in charge of removing the session at the expiration date, it just holds the expiration date</b>
	 *
	 * @param expirationDate to be the value of the expirationDate
	 */
	void setExpirationDate(long expirationDate)
	{
		this.expirationDate.set(expirationDate);
	}
	
	/**
	 * @return the expiration date ({@code null} if there isn't an expiration date)
	 */
	Long getExpirationDate()
	{
		return expirationDate.get();
	}
	
	SymmetricKeyRatchet getSendingRatchet()
	{
		return sendingRatchet;
	}
	
	KeyPair getSignatureKeyPair()
	{
		return signatureKeyPair.get();
	}
	
	/**
	 * @return a collection of known members associated with this session
	 */
	Collection<UserDeviceUID> getKnownMembers()
	{
		return receivingRatchets.keySet();
	}
}