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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.TimeUnit;

import oughttoprevail.prevailprotocol.User;
import oughttoprevail.prevailprotocol.asymmetriccryptography.AsymmetricCryptography;
import oughttoprevail.prevailprotocol.exception.CounterTooLargeException;
import oughttoprevail.prevailprotocol.kdf.KDF;
import oughttoprevail.prevailprotocol.kdf.SimpleKDF;
import oughttoprevail.prevailprotocol.messenger.ByteArrayReader;
import oughttoprevail.prevailprotocol.messenger.ConsumerReader;
import oughttoprevail.prevailprotocol.messenger.EncryptedMessage;
import oughttoprevail.prevailprotocol.messenger.MessageKeys;
import oughttoprevail.prevailprotocol.messenger.Reader;
import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.Directory;
import oughttoprevail.prevailprotocol.storage.SkippedKeysStorage;
import oughttoprevail.prevailprotocol.storage.Storage;
import oughttoprevail.prevailprotocol.storage.fields.CounterField;
import oughttoprevail.prevailprotocol.uid.RecipientUser;
import oughttoprevail.prevailprotocol.uid.UID;
import oughttoprevail.prevailprotocol.uid.UserDeviceUID;
import oughttoprevail.prevailprotocol.util.Consumer;

/**
 * A {@link Group} allows for a conversation with lots of recipients with better performance then having lots of pairwise conversations which use
 * {@link oughttoprevail.prevailprotocol.session.Session}.
 * {@link Group} comes with downsides:
 * 1. The {@link oughttoprevail.prevailprotocol.doubleratchet.DHRatchet} isn't involved anymore (meaning the <a href="https://en.wikipedia.org/wiki/Double_Ratchet_Algorithm">self healing</a> effect is lost).
 * 2. {@link Group} removes <a href="https://en.wikipedia.org/wiki/Deniable_authentication">Deniable Authentication</a>
 */
public class Group
{
	/**
	 * Directory name for groups
	 */
	private static final String GROUPS_DIRECTORY = "Groups";
	/**
	 * Group storage name
	 */
	private static final String GROUP_STORAGE = "Group";
	/**
	 * Group session storage name
	 */
	private static final String SESSION_DIRECTORY = "Session";
	
	/**
	 * List of group sessions, at first, there is a single {@link GroupSession} and whenever a member leaves a new {@link GroupSession} is initiated.
	 * A new {@link GroupSession} is initiated whenever a member leaves so a member cannot decrypt a new message with the ciphertext and the sender
	 * key.
	 */
	private final List<GroupSession> sessions;
	/**
	 * Group storage
	 */
	private final Storage storage;
	/**
	 * User who created this group
	 */
	private final User user;
	/**
	 * For {@link oughttoprevail.prevailprotocol.doubleratchet.SymmetricKeyRatchet}
	 */
	private final KDF kdf;
	/**
	 * For {@link oughttoprevail.prevailprotocol.doubleratchet.SymmetricKeyRatchet}
	 */
	private final SimpleKDF simpleKDF;
	/**
	 * Settings to use
	 */
	private final Settings settings;
	/**
	 * Directory for all storage of this group
	 */
	private final Directory groupDirectory;
	/**
	 * Amount of stored {@link GroupSession}s
	 */
	private final CounterField totalGroupSessions;
	/**
	 * List of all members of this group
	 */
	private final List<RecipientUser> members;
	/**
	 * Storage for skipped keys
	 */
	private final SkippedKeysStorage skippedKeysStorage;
	
	/**
	 * Constructs a new {@link Group}.
	 *
	 * @param user who created this group
	 * @param kdf for {@link oughttoprevail.prevailprotocol.doubleratchet.SymmetricKeyRatchet}
	 * @param simpleKDF for {@link oughttoprevail.prevailprotocol.doubleratchet.SymmetricKeyRatchet}
	 * @param userDirectory is the directory of the specified user
	 * @param groupId is the identifier of this group
	 * @param settings to use
	 */
	public Group(User user, KDF kdf, SimpleKDF simpleKDF, Directory userDirectory, UID groupId, Settings settings)
	{
		this.user = user;
		this.kdf = kdf;
		this.simpleKDF = simpleKDF;
		this.settings = settings;
		this.sessions = new ArrayList<>();
		this.groupDirectory = userDirectory.directory(GROUPS_DIRECTORY).directory(groupId.toString());
		this.storage = groupDirectory.storage(GROUP_STORAGE);
		this.totalGroupSessions = new CounterField(storage);
		this.members = storage.getFieldList(RecipientUser.SER_DES);
		this.skippedKeysStorage = settings.getMaxSkipKeys() == 0 ? null : new SkippedKeysStorage(userDirectory, settings);
		int size = totalGroupSessions.get();
		if(size == 0)
		{
			//if size is 0 then this is a new group
			addSession(true);
			return;
		}
		//add all sessions
		for(int i = size; i > 0; i--)
		{
			GroupSession session = addSession(false);
			Long expirationDate = session.getExpirationDate();
			//schedule for removal if there is an expiration date
			if(expirationDate != null)
			{
				settings.getScheduler().schedule(() -> sessions.remove(session), expirationDate, TimeUnit.MILLISECONDS);
			}
		}
	}
	
	/**
	 * Encrypts the sender key of this user to be sent to all the devices of the specified userId.
	 *
	 * @param userId is the recipient to receive the sender key
	 * @return the encrypted sender key for all the recipient (specified userId) devices
	 */
	public EncryptedMessage[] encryptSenderKey(UID userId)
			throws IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException
	{
		return user.encryptMessage(userId, getNewestSession().createSenderKey(), false);
	}
	
	/**
	 * Encrypts the sender key of this user to be sent to the specified userDeviceUID.
	 *
	 * @param userDeviceUID is the user device recipient to receive the sender key
	 * @return the encrypted sender key
	 */
	public byte[] encryptSenderKey(UserDeviceUID userDeviceUID)
			throws InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException
	{
		return user.getMessenger(userDeviceUID).encryptMessage(getNewestSession().createSenderKey());
	}
	
	/**
	 * Joins the specified userDeviceUID with the specified senderKey to this group.
	 *
	 * @param userDeviceUID is the identifier of the joining user device
	 * @param senderKey of the joining user device
	 */
	public void memberJoined(UserDeviceUID userDeviceUID, byte[] senderKey)
	{
		RecipientUser.add(storage, members, userDeviceUID);
		getNewestSession().memberJoined(userDeviceUID, senderKey);
	}
	
	/**
	 * Leaves the specified userDeviceUID from this group.
	 *
	 * @param userDeviceUID who is leaving
	 * @return an array of {@link EncryptedMessage} to be sent to all current group members with the new values of the new session
	 */
	public EncryptedMessage[] memberLeft(UserDeviceUID userDeviceUID)
			throws IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException
	{
		//if the newest session can't find the member then he isn't in the group
		GroupSession newestSession = getNewestSession();
		if(newestSession.memberLeft(userDeviceUID))
		{
			return null;
		}
		Iterator<RecipientUser> iterator = members.iterator();
		//remove him from members list
		while(iterator.hasNext())
		{
			RecipientUser recipientUser = iterator.next();
			if(recipientUser.getUserId().equals(userDeviceUID.getUserId()) && recipientUser.getDeviceIds().remove(userDeviceUID.getDeviceId()))
			{
				iterator.remove();
				storage.flush();
			}
		}
		//schedule it for deletion
		long groupSessionDeletionKeepAlive = settings.getGroupSessionDeletionKeepAlive();
		newestSession.setExpirationDate(System.currentTimeMillis() + groupSessionDeletionKeepAlive);
		settings.getScheduler().schedule(() -> sessions.remove(newestSession), groupSessionDeletionKeepAlive, TimeUnit.MILLISECONDS);
		for(GroupSession session : sessions)
		{
			//if a session says it couldn't find the member the next session shouldn't have the member as well so we should stop
			if(session.memberLeft(userDeviceUID))
			{
				break;
			}
		}
		//create a new session and send new sender key
		GroupSession session = addSession(true);
		return session.encryptSenderKeyToAll();
	}
	
	/**
	 * Creates a new {@link GroupSession} then adds it to the {@link #sessions}.
	 *
	 * @param newSession whether this is a new session or a loaded one ({@code true} for new session and {@code false} for loaded)
	 * @return the created and added {@link GroupSession}
	 */
	private GroupSession addSession(boolean newSession)
	{
		GroupSession session = new GroupSession(user,
				kdf,
				simpleKDF,
				groupDirectory.directory(SESSION_DIRECTORY + sessions.size()),
				skippedKeysStorage,
				members,
				settings);
		sessions.add(session);
		if(newSession)
		{
			totalGroupSessions.increment();
			storage.flush();
		}
		return session;
	}
	
	/**
	 * Encrypts the specified message for all the current known group.
	 *
	 * @param message to encrypt
	 * @return the encrypted group message
	 */
	public EncryptedGroupMessage encryptMessage(byte[] message)
			throws IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException
	{
		GroupSession groupSession = getNewestSession();
		GroupMessenger messenger = groupSession.getMessenger();
		byte[] ciphertext = messenger.encryptMessage(message);
		return new EncryptedGroupMessage(groupSession.getKnownMembers(), ciphertext);
	}
	
	/**
	 * Decrypts the specified message.
	 *
	 * @param userDeviceUID is the sender of the message
	 * @param message to decrypt
	 * @return the decrypted (plaintext) message
	 */
	public byte[] decryptMessage(UserDeviceUID userDeviceUID, byte[] message)
			throws IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, CounterTooLargeException
	{
		return decryptMessage(userDeviceUID, new ByteArrayReader(message));
	}
	
	/**
	 * Decrypts a message using the specified reader.
	 *
	 * @param userDeviceUID is the sender of the message
	 * @param reader to read the message with
	 * @return the decrypted (plaintext) message
	 */
	public byte[] decryptMessage(UserDeviceUID userDeviceUID, Reader reader)
			throws InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, CounterTooLargeException
	{
		int receivedCounter = reader.readInt();
		byte[] signature = reader.readBytes(settings.getAsymmetricCryptography().getSignatureSize());
		int ciphertextLength = reader.readInt();
		byte[] ciphertext = reader.readBytes(ciphertextLength);
		return decryptMessage(userDeviceUID, receivedCounter, signature, ciphertext);
	}
	
	/**
	 * Decrypts a message using the specified reader then invokes the specified decryptionConsumer with the decrypted message.
	 *
	 * @param userDeviceUID is the sender of the message
	 * @param reader to read the message with
	 * @param decryptionConsumer to invoke with the decrypted message
	 * @param exceptionCatcher to invoke with exceptions if any occur
	 */
	public void decryptMessage(UserDeviceUID userDeviceUID,
							   ConsumerReader reader,
							   Consumer<byte[]> decryptionConsumer,
							   Consumer<Throwable> exceptionCatcher)
	{
		reader.readInt(receivedCounter -> reader.readBytes(signature -> reader.readInt(ciphertextLength -> reader.readBytes(ciphertext ->
		{
			try
			{
				decryptionConsumer.accept(decryptMessage(userDeviceUID, receivedCounter, signature, ciphertext));
			} catch(IllegalBlockSizeException | InvalidAlgorithmParameterException | BadPaddingException | CounterTooLargeException | InvalidKeyException e)
			{
				exceptionCatcher.accept(e);
			}
		}, ciphertextLength)), settings.getAsymmetricCryptography().getSignatureSize()));
	}
	
	/**
	 * Decrypts the specified ciphertext using the specified parameters.
	 *
	 * @param receivedCounter is the sender's counter of the symmetric ratchet before the {@link MessageKeys} used to encrypt the specified ciphertext
	 * were generated
	 * @param signature the ciphertext signature
	 * @param ciphertext to decrypt
	 * @return the decrypted (plaintext) message
	 */
	public byte[] decryptMessage(UserDeviceUID userDeviceUID, int receivedCounter, byte[] signature, byte[] ciphertext)
			throws IllegalBlockSizeException, InvalidAlgorithmParameterException, BadPaddingException, CounterTooLargeException, InvalidKeyException
	{
		AsymmetricCryptography asymmetricCryptography = settings.getAsymmetricCryptography();
		for(GroupSession groupSession : sessions)
		{
			SignatureNRatchet signatureNRatchet;
			/*
			if SignatureNRatchet are null, it means at the current session (groupSession) is from before the member joined or if it is the first
			session then the member never joined
			 */
			if((signatureNRatchet = groupSession.getSignatureNRatchet(userDeviceUID)) == null)
			{
				break;
			}
			byte[] signatureKey = signatureNRatchet.getSignatureKey();
			if(!asymmetricCryptography.verify(signature, ciphertext, signatureKey))
			{
				continue;
			}
			return groupSession.getMessenger().decryptMessage(receivedCounter, ciphertext, signatureNRatchet);
		}
		return null;
	}
	
	/**
	 * @return the newest session
	 */
	private GroupSession getNewestSession()
	{
		return sessions.get(sessions.size() - 1);
	}
	
	/**
	 * @return all the members known in this group
	 */
	public Collection<UserDeviceUID> getMembers()
	{
		//instead of using the members list we have here we use the one from the newest session, because the member list we have isn't UserDeviceUID
		return getNewestSession().getKnownMembers();
	}
	
	/**
	 * @param userId to check whether is in the group
	 * @return whether a member with the specified userId is in the group
	 */
	public boolean hasMember(UID userId)
	{
		Collection<UserDeviceUID> members = getMembers();
		for(UserDeviceUID member : members)
		{
			if(member.getUserId().equals(userId))
			{
				return true;
			}
		}
		return false;
	}
	
	/**
	 * @param userDeviceUID to check whether is in the group
	 * @return whether a member with the specified userDeviceUID is in the group
	 */
	public boolean hasMember(UserDeviceUID userDeviceUID)
	{
		Collection<UserDeviceUID> members = getMembers();
		return members.contains(userDeviceUID);
	}
}