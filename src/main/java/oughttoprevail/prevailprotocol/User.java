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
package oughttoprevail.prevailprotocol;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import oughttoprevail.prevailprotocol.cipher.MessengerCipher;
import oughttoprevail.prevailprotocol.doubleratchet.SymmetricKeyRatchet;
import oughttoprevail.prevailprotocol.exception.TooManyDevicesException;
import oughttoprevail.prevailprotocol.exception.VerificationFailedException;
import oughttoprevail.prevailprotocol.fingerprint.FingerprintHandler;
import oughttoprevail.prevailprotocol.group.Group;
import oughttoprevail.prevailprotocol.kdf.KDF;
import oughttoprevail.prevailprotocol.kdf.SimpleKDF;
import oughttoprevail.prevailprotocol.keys.DataBundle;
import oughttoprevail.prevailprotocol.keys.IdentifiableKey;
import oughttoprevail.prevailprotocol.keys.IdentifiableKeyPair;
import oughttoprevail.prevailprotocol.keys.KeyPair;
import oughttoprevail.prevailprotocol.keys.SavedDataBundle;
import oughttoprevail.prevailprotocol.keys.SignedPreKey;
import oughttoprevail.prevailprotocol.messenger.EncryptedMessage;
import oughttoprevail.prevailprotocol.messenger.Messenger;
import oughttoprevail.prevailprotocol.rw.ByteArrayOutput;
import oughttoprevail.prevailprotocol.rw.FixedByteBufferInput;
import oughttoprevail.prevailprotocol.session.Session;
import oughttoprevail.prevailprotocol.session.SessionsManager;
import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.Directory;
import oughttoprevail.prevailprotocol.storage.UserStorage;
import oughttoprevail.prevailprotocol.uid.RecipientUser;
import oughttoprevail.prevailprotocol.uid.UID;
import oughttoprevail.prevailprotocol.uid.UIDFactory;
import oughttoprevail.prevailprotocol.uid.UserDeviceUID;
import oughttoprevail.prevailprotocol.util.Consumer;
import oughttoprevail.prevailprotocol.util.Util;
import oughttoprevail.prevailprotocol.x3dh.X3DHKeyExchange;

/**
 * A local user manager class.
 */
public class User
{
	/**
	 * Directory name of users
	 */
	private static final String USERS_DIRECTORY = "Users";
	
	/**
	 * Directory of this user, all storage for this user will be defined under this directory
	 */
	private final Directory userDirectory;
	/**
	 * Defines the storage for this user and this user only, it will not include sessions nor messages, only the storage relating to this user.
	 */
	private final UserStorage userStorage;
	/**
	 * The cipher of this user which will be used to encrypt and decrypt messages
	 */
	private final MessengerCipher cipher;
	/**
	 * A boolean whether to store skipped keys. If {@code true} then skipped keys will be stored in a {@link
	 * oughttoprevail.prevailprotocol.storage.SkippedKeysStorage}, if {@code false} then keys will be skipped and ignored
	 */
	private final boolean storeSkippedKeys;
	/**
	 * The settings of the this user, the behavior of this user will be defined by these settings
	 */
	private final Settings settings;
	/**
	 * The dataBundle of this user, the dataBundle will always be null unless this is a new device and the user has yet to send the dataBundle to the
	 * server
	 */
	private DataBundle dataBundle;
	/**
	 * The savedDataBundle will have the information required for this user
	 */
	private SavedDataBundle savedDataBundle;
	/**
	 * The Mac object of this user, it will be used when authentication is required to generate a message authentication code (MAC)
	 */
	private final Mac mac;
	/**
	 * The KDF for this user, will be used to derive new keys and add future secrecy
	 */
	private final KDF kdf;
	/**
	 * The simpleKDF assists the {@link SymmetricKeyRatchet} used by {@link Session} to derive keys
	 */
	private final SimpleKDF simpleKDF;
	/**
	 * This device user unique identifier
	 */
	private final UserDeviceUID userDeviceUID;
	/**
	 * A map of user identifier to sessions list. The key defines the recipient by his userId and the value defines the sessions manager which this
	 * recipient has created with this recipient
	 */
	private final Map<UID, SessionsManager> sessions;
	/**
	 * A map of group identifier to group
	 */
	private final Map<UID, Group> groups;
	/**
	 * A boolean defining whether this is a loaded from storage device or a new device. If {@code true} it means this is a new device if {@code false}
	 * it means this device was loaded from storage
	 */
	private final boolean newDevice;
	/**
	 * A list of {@link Consumer}s to be executed when a signed pre key changes. All runnable will be executed every time a signed pre key changes
	 * with the new signed pre key value
	 */
	private final List<Consumer<SignedPreKey>> onSignedPreKeyChange = new ArrayList<>();
	/**
	 * The fingerprint handler of this user, this may be {@code null}
	 */
	private FingerprintHandler fingerprintHandler;
	
	/**
	 * Constructs a new user with the specified userId, {@link Settings#getDefaultSettings()} as the settings and {@link MessengerCipher} as the
	 * cipher.
	 *
	 * @param userId is the identifier of this user, it must be unique per user
	 */
	public User(UID userId) throws NoSuchAlgorithmException, NoSuchPaddingException
	{
		this(userId, Settings.getDefaultSettings());
	}
	
	/**
	 * Constructs a new user with the specified userId, specified settings and specified cipher.
	 *
	 * @param userId is the identifier of this user, it must be unique per user
	 */
	public User(UID userId, Settings settings) throws NoSuchAlgorithmException, NoSuchPaddingException
	{
		//create user directory
		userDirectory = settings.getInitialDirectory().directory(USERS_DIRECTORY).directory(userId.toString());
		//create storage
		this.userStorage = new UserStorage(userDirectory, settings);
		//define whether skipped keys will be stored
		this.storeSkippedKeys = settings.getMaxSkipKeys() != 0;
		this.settings = settings;
		//get the device id
		UID myDeviceId = userStorage.getDeviceId();
		//set whether this is a new device by whether the device id is null
		newDevice = myDeviceId == null;
		if(newDevice)
		{
			//create a new device id and save it
			myDeviceId = settings.getUIDFactory().generateUID();
			userStorage.setDeviceId(myDeviceId);
		}
		this.userDeviceUID = new UserDeviceUID(userId, myDeviceId);
		//get data bundle and saved data bundle from storage
		//if dataBundle and savedDataBundle is null we need to create a new data bundle
		if(newDevice)
		{
			//create a new data bundle and save it
			dataBundle = DataBundle.newBundle(settings);
			userStorage.setDataBundle(dataBundle);
		} else
		{
			//set the dataBundle to null
			dataBundle = userStorage.getDataBundle();
			savedDataBundle = userStorage.getSavedDataBundle();
		}
		//create a new mac
		String macAlgorithm = settings.getMacAlgorithm();
		Provider provider = settings.getProvider();
		this.mac = provider == null ? Mac.getInstance(macAlgorithm) : Mac.getInstance(macAlgorithm, provider);
		//create a new kdf's
		this.kdf = settings.getKDFFactory().newKDF(mac, settings);
		this.simpleKDF = new SimpleKDF(mac, settings);
		//create a cipher
		this.cipher = new MessengerCipher(settings);
		//create maps
		this.sessions = new HashMap<>();
		this.groups = new HashMap<>();
		//get recipient users
		List<RecipientUser> recipientUsers = userStorage.getRecipientUsers();
		//loop through all recipient users and their devices and add the session if they have a key agreement
		for(RecipientUser userField : recipientUsers)
		{
			UID recipientUserId = userField.getUserId();
			List<UID> deviceIds = userField.getDeviceIds();
			for(UID recipientDeviceId : deviceIds)
			{
				SessionsManager sessionsManager = getOrCreateSessionsList(recipientUserId);
				Session session = createSession(sessionsManager, new UserDeviceUID(recipientUserId, recipientDeviceId), true);
				sessionsManager.addSession(session);
			}
		}
		scheduleSignedPreKeys();
	}
	
	/**
	 * Schedules signedPreKeys to be changed after a certain amount of time
	 */
	private void scheduleSignedPreKeys()
	{
		SignedPreKey signedPreKey = dataBundle == null ? savedDataBundle.getSignedPreKey() : dataBundle.getSignedPreKey();
		ScheduledExecutorService scheduler = settings.getScheduler();
		long timeLeft = calculateTimeLeft(signedPreKey);
		//schedule the signed pre keys change, if the timeLeft is negative or 0, it will be executed immediately
		scheduler.schedule(new Runnable()
		{
			@Override
			public void run()
			{
				//generate new signed pre key and change it in storage
				SignedPreKey newSignedPreKey = DataBundle.generateSignedPreKey(dataBundle == null
																			   ? savedDataBundle.getIdentityKey()
																			   : dataBundle.getIdentityKeys(), settings);
				savedDataBundle.changeSignedPreKey(newSignedPreKey);
				//invoke onSignedPreKeyChange consumers
				for(Consumer<SignedPreKey> signedPreKeyConsumer : onSignedPreKeyChange)
				{
					signedPreKeyConsumer.accept(newSignedPreKey);
				}
				//re-schedule for a new change
				scheduler.schedule(this, calculateTimeLeft(signedPreKey), TimeUnit.MILLISECONDS);
			}
		}, timeLeft, TimeUnit.MILLISECONDS);
	}
	
	/**
	 * Calculates and returns the time left for the signedPreKey based on the current time and end time
	 *
	 * @param signedPreKey to calculate the time left for
	 * @return how much time in millis is left until a signed pre key should change
	 */
	private long calculateTimeLeft(SignedPreKey signedPreKey)
	{
		//subtract the time it ends to to the current time to result in the time left
		return signedPreKey.getExpirationTime() - System.currentTimeMillis();
	}
	
	/**
	 * Adds the specified consumer to a onSignedPreKeyChange list. Every consumer in the list will be invoked in the order it was added.
	 *
	 * @param onSignedPreKeyChange consumer to be invoked when a signed pre key has changed
	 */
	public void onSignedPreKeyChange(Consumer<SignedPreKey> onSignedPreKeyChange)
	{
		this.onSignedPreKeyChange.add(onSignedPreKeyChange);
	}
	
	/**
	 * Signs and returns a signed nonce (based on the specified nonce). If the specified nonce doesn't match nonce size in {@link
	 * Settings#getNonceSize()} this returns {@code null}. This can be used for recipient or third party (such as the server) to verify that the user
	 * has the IdentityPrivateKey. The specified nonce should be a truly nonce (number used once) to defend against replay attacks.
	 *
	 * @param nonce to sign
	 * @return the signed nonce
	 */
	public byte[] signNonce(byte[] nonce)
	{
		if(nonce.length != settings.getNonceSize())
		{
			return null;
		}
		return settings.getAsymmetricCryptography().sign(nonce, getIdentityPrivateKey());
	}
	
	/**
	 * Registers the specified "Bob" (receiving) with this user acting as the role "Alice" (initiator) in the session creation.
	 * If "Bob" wants to register "Alice" he will receive the registerMessage from either {@link Messenger#encryptMessage(byte[])}
	 * or {@link Session#getRegisterMessage()} and will invoke {@link #bobRegister(UserDeviceUID, byte[])}.
	 *
	 * @param bobUserDeviceUID is "Bob"'s identifiers
	 * @param identityKey is "Bob"'s identity key
	 * @param signedPreKey is "Bob"'s signed pre key
	 * @param preKeySignature is "Bob"'s pre key signature
	 * @param oneTimePreKey is "Bob"'s one time pre key
	 * @return the new session created for the specified device, if the specified device failed verification {@code null} will be returned.
	 * @throws InvalidKeyException if an invalid key was used during registration
	 * @throws TooManyDevicesException if the current amount of devices is equal to {@link Settings#getMaxDevices()} so adding a new device would pass
	 * the maximum
	 * @throws VerificationFailedException if the specified device failed verification
	 */
	public Session aliceRegister(UserDeviceUID bobUserDeviceUID,
								 byte[] identityKey,
								 IdentifiableKey signedPreKey,
								 byte[] preKeySignature,
								 IdentifiableKey oneTimePreKey) throws InvalidKeyException, TooManyDevicesException, VerificationFailedException
	{
		SessionsManager sessionsManager = getOrCreateSessionsList(bobUserDeviceUID.getUserId());
		sessionsManager.ensureCanAddDevice(settings);
		Session session = createSession(sessionsManager, bobUserDeviceUID, false);
		
		KeyPair ephemeralKeyPair = settings.getAsymmetricCryptography().generateKeyPair();
		X3DHKeyExchange.aliceKeyAgreement(session,
				getIdentityPrivateKey(),
				ephemeralKeyPair,
				identityKey,
				signedPreKey.getKey(),
				preKeySignature,
				oneTimePreKey == null ? null : oneTimePreKey.getKey(),
				settings);
		
		boolean hasOneTimePreKey = oneTimePreKey != null;
		ByteArrayOutput uidOutput = new ByteArrayOutput(ByteBuffer.allocate(32), settings);
		UIDFactory uidFactory = settings.getUIDFactory();
		uidOutput.writeObject(signedPreKey.getUID(), uidFactory);
		uidOutput.writeBoolean(hasOneTimePreKey);
		if(hasOneTimePreKey)
		{
			uidOutput.writeObject(oneTimePreKey.getUID(), uidFactory);
		}
		byte[] bytes = uidOutput.toByteArray();
		
		byte[] registerMessage = Util.combine(getIdentityPublicKey(), ephemeralKeyPair.getPublicKey(), bytes);
		session.setRegisterMessage(registerMessage);
		registerSession(sessionsManager, session);
		return session;
	}
	
	/**
	 * Registers the specified device using the specified registerMessage. This user will be "Bob" and the specified userId and deviceId will be
	 * "Alice".
	 *
	 * @param aliceUserDeviceUID is "Alice"'s identifiers
	 * @param registerMessage is the message containing the data bundle of "Alice", this can be found in {@link Session#getRegisterMessage()} and in
	 * the start of initial messages encrypted using {@link Messenger#encryptMessage(byte[])}
	 * @return the new session created for the specified device
	 * @throws InvalidKeyException if an invalid key was used during registration
	 * @throws TooManyDevicesException if the current amount of devices is equal to {@link Settings#getMaxDevices()} so adding a new device would pass
	 * the maximum
	 */
	public Session bobRegister(UserDeviceUID aliceUserDeviceUID, byte[] registerMessage) throws InvalidKeyException, TooManyDevicesException
	{
		ByteBuffer byteBuffer = ByteBuffer.wrap(registerMessage);
		int publicKeySize = settings.getAsymmetricCryptography().getPublicKeySize();
		byte[] identityKey = new byte[publicKeySize];
		byteBuffer.get(identityKey);
		byte[] ephemeralKey = new byte[publicKeySize];
		byteBuffer.get(ephemeralKey);
		UIDFactory uidFactory = settings.getUIDFactory();
		int position = byteBuffer.position();
		int limit = byteBuffer.limit();
		byteBuffer.position(position);
		byteBuffer.limit(limit);
		FixedByteBufferInput uidInput = new FixedByteBufferInput(byteBuffer, settings);
		UID signedPreKeyUID = uidInput.readObject(uidFactory);
		boolean hasOneTimePreKey = uidInput.readBoolean();
		UID oneTimePreKeyUID = null;
		if(hasOneTimePreKey)
		{
			oneTimePreKeyUID = uidInput.readObject(uidFactory);
		}
		return bobRegister(aliceUserDeviceUID, identityKey, ephemeralKey, signedPreKeyUID, oneTimePreKeyUID);
	}
	
	/**
	 * Registers the specified device. This user will be "Bob" and the specified userId and deviceId will be "Alice".
	 *
	 * @param aliceUserDeviceUID is "Alice"'s identifiers
	 * @param identityKey is the identity key of "Alice"
	 * @param ephemeralKey is the ephemeralKey of "Alice", the ephemeralKey is only used for this session
	 * @param signedPreKeyUID is identifier of the signedPreKey "Alice" used
	 * @param oneTimePreKeyUID is the identifier of the oneTimePreKey "Alice" used
	 * @return the new session created for the specified device
	 * @throws InvalidKeyException if an invalid key was used during registration
	 * @throws TooManyDevicesException if the current amount of devices is equal to {@link Settings#getMaxDevices()} so adding a new device would pass
	 * the maximum
	 */
	public Session bobRegister(UserDeviceUID aliceUserDeviceUID, byte[] identityKey, byte[] ephemeralKey, UID signedPreKeyUID, UID oneTimePreKeyUID)
			throws TooManyDevicesException, InvalidKeyException
	{
		SessionsManager sessionsManager = getOrCreateSessionsList(aliceUserDeviceUID.getUserId());
		sessionsManager.ensureCanAddDevice(settings);
		IdentifiableKeyPair signedPreKey = savedDataBundle.findSignedPreKey(signedPreKeyUID);
		IdentifiableKey oneTimePreKey = null;
		if(oneTimePreKeyUID != null)
		{
			oneTimePreKey = savedDataBundle.removeOneTimePreKey(oneTimePreKeyUID);
		}
		Session bobSession = createSession(sessionsManager, aliceUserDeviceUID, false);
		X3DHKeyExchange.bobKeyAgreement(bobSession, getIdentityPrivateKey(), identityKey, signedPreKey, oneTimePreKey, ephemeralKey, settings);
		registerSession(sessionsManager, bobSession);
		return bobSession;
	}
	
	/**
	 * Adds the specified session to the specified sessionsManager and adds the specified userId with the deviceId of the session to the {@link
	 * UserStorage} recipient ids.
	 *
	 * @param sessionsManager to add the specified session to
	 * @param session to add to the specified sessionsManager
	 */
	private void registerSession(SessionsManager sessionsManager, Session session)
	{
		sessionsManager.addSession(session);
		if(fingerprintHandler != null)
		{
			List<Consumer<UID>> onFingerprintChange = fingerprintHandler.getOnFingerprintChange();
			for(Consumer<UID> consumer : onFingerprintChange)
			{
				consumer.accept(session.getRecipientUserDeviceUID().getUserId());
			}
		}
		userStorage.addRecipientIds(session.getRecipientUserDeviceUID());
	}
	
	/**
	 * Creates and returns a new {@link Session} for the specified sessionsManager.
	 *
	 * @param sessionsManager to create the session for
	 * @param recipientUserDeviceUIUD is the identifiers of the user device which the session is being created for
	 * @param loadedSession whether this session was loaded from storage or it is a new {@link Session}
	 * @return new session for the specified sessionsManager
	 */
	private Session createSession(SessionsManager sessionsManager, UserDeviceUID recipientUserDeviceUIUD, boolean loadedSession)
	{
		Directory userDirectory = sessionsManager.getUserDirectory();
		return new Session(userDirectory, this, storeSkippedKeys, kdf, simpleKDF, recipientUserDeviceUIUD, loadedSession, settings);
	}
	
	/**
	 * Gets the {@link SessionsManager} for the specified userId, or if one doesn't exist a new {@link SessionsManager} is created.
	 *
	 * @param userId to get or create {@link SessionsManager} for
	 * @return a {@link SessionsManager} for the specified userId
	 */
	private SessionsManager getOrCreateSessionsList(UID userId)
	{
		SessionsManager sessionsManager = sessions.get(userId);
		if(sessionsManager == null)
		{
			Directory recipientUserDirectory = userDirectory.directory(userId.toString());
			sessionsManager = new SessionsManager(recipientUserDirectory);
			sessions.put(userId, sessionsManager);
		}
		return sessionsManager;
	}
	
	/**
	 * Encrypts the specified message for the specified userId.
	 *
	 * @param userId recipient user to encrypt the message for
	 * @param message to encrypt
	 * @return an array of {@link EncryptedMessage}, each element with it's destination and encrypted message. This {@link EncryptedMessage} array should
	 * have 2 destination, one for the registered sessions for this user and one for the registered sessions for the specified userId
	 */
	public EncryptedMessage[] encryptMessage(UID userId, byte[] message)
			throws IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException
	{
		return encryptMessage(userId, message, true);
	}
	
	/**
	 * Encrypts the specified message for the specified userId.
	 *
	 * @param userId recipient user to encrypt the message for
	 * @param message to encrypt
	 * @param addMyDevices {@code true} if all other devices of this user should also be included with an encrypted message in the returned array
	 * @return an array of {@link EncryptedMessage}, each element with it's destination and encrypted message
	 */
	public EncryptedMessage[] encryptMessage(UID userId, byte[] message, boolean addMyDevices)
			throws InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException
	{
		//get session
		SessionsManager recipientSessionsManager = sessions.get(userId);
		if(recipientSessionsManager == null)
		{
			return null;
		}
		Collection<Session> sessions = recipientSessionsManager.sessions();
		EncryptedMessage[] messages;
		int index = 0;
		SessionsManager mySessionsManager;
		//add all the devices from this user sessions if there any and if addMyDevices is true
		if(addMyDevices && (mySessionsManager = this.sessions.get(userDeviceUID.getUserId())) != null)
		{
			Collection<Session> myUserSessions = mySessionsManager.sessions();
			messages = new EncryptedMessage[sessions.size() + myUserSessions.size()];
			for(Session session : myUserSessions)
			{
				messages[index++] = createMessage(session, message);
			}
		} else
		{
			messages = new EncryptedMessage[sessions.size()];
		}
		for(Session session : sessions)
		{
			messages[index++] = createMessage(session, message);
		}
		return messages;
	}
	
	/**
	 * Creates an {@link EncryptedMessage} for the specified plaintext message using the specified parameters.
	 *
	 * @param session to create message with
	 * @param message plaintext message
	 * @return a new {@link EncryptedMessage} based on the specified parameters
	 */
	private EncryptedMessage createMessage(Session session, byte[] message)
			throws InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException
	{
		return new EncryptedMessage(session.getRecipientUserDeviceUID(), session.getMessenger().encryptMessage(message));
	}
	
	/**
	 * @param userDeviceUID of the requested session
	 * @return the session for the specified userDeviceUID.
	 */
	public Session getSession(UserDeviceUID userDeviceUID)
	{
		SessionsManager sessionsManager = sessions.get(userDeviceUID.getUserId());
		return sessionsManager == null ? null : sessionsManager.getSession(userDeviceUID.getDeviceId());
	}
	
	/**
	 * This can be used to know whether a device needs to be registered or not by checking if it doesn't have a session.
	 *
	 * @param userDeviceUID of the session
	 * @return whether the specified userId and deviceId have a session
	 */
	public boolean hasSession(UserDeviceUID userDeviceUID)
	{
		return getSession(userDeviceUID) != null;
	}
	
	/**
	 * @param userDeviceUID to get the {@link Messenger} of
	 * @return the {@link Messenger} for the specified userDeviceId.
	 * If the specified userDeviceId have a session then the sessions's {@link Messenger} will be returned.
	 * If the specified userDeviceId don't have a session then a new {@link Messenger} will be returned, this {@link Messenger}
	 * will <b>only</b> be able to decrypt messages with a {@link Session#getRegisterMessage()} sent by the other party ("Alice") after it has
	 * successfully decrypted a message it will also be able to encrypt {@link Messenger}, this {@link Messenger} will not be
	 * equal to the one from {@link Session#getMessenger()}
	 */
	public Messenger getMessenger(UserDeviceUID userDeviceUID)
	{
		Session session = getSession(userDeviceUID);
		return session == null ? new Messenger(this, userDeviceUID, settings) : session.getMessenger();
	}
	
	/**
	 * Deletes the session for the specified userId and specified deviceId.
	 *
	 * @param userDeviceUID of the session to be deleted
	 * @return whether the session was deleted
	 */
	public boolean deleteSession(UserDeviceUID userDeviceUID)
	{
		SessionsManager sessionsManager = sessions.get(userDeviceUID.getUserId());
		if(sessionsManager != null)
		{
			return sessionsManager.deleteSession(userStorage, userDeviceUID);
		}
		return false;
	}
	
	/**
	 * Deletes all sessions related to the specified userId recipient.
	 *
	 * @param userId to delete
	 * @return whether the sessions have been deleted
	 */
	public boolean deleteRecipient(UID userId)
	{
		SessionsManager sessionsManager = sessions.remove(userId);
		if(sessionsManager != null)
		{
			sessionsManager.getUserDirectory().delete();
			return true;
		}
		return false;
	}
	
	/**
	 * Deletes all data related to this user
	 */
	public void deleteUser()
	{
		userStorage.delete();
	}
	
	/**
	 * @return a new or already created {@link FingerprintHandler} of this user
	 */
	public FingerprintHandler getOrCreateFingerprintHandler() throws NoSuchAlgorithmException
	{
		if(fingerprintHandler == null)
		{
			fingerprintHandler = new FingerprintHandler(this, settings);
		}
		return fingerprintHandler;
	}
	
	/**
	 * @param groupId to get/create {@link Group} for
	 * @return a new or already created {@link Group} with the specified groupId
	 */
	public Group getOrCreateGroup(UID groupId)
	{
		Group group;
		if((group = groups.get(groupId)) != null)
		{
			return group;
		}
		groups.put(groupId, group = new Group(this, kdf, simpleKDF, userDirectory, groupId, settings));
		return group;
	}
	
	public UserDeviceUID getUserDeviceUID()
	{
		return userDeviceUID;
	}
	
	public byte[] getIdentityPublicKey()
	{
		return savedDataBundle.getIdentityKey().getPublicKey();
	}
	
	private byte[] getIdentityPrivateKey()
	{
		return savedDataBundle.getIdentityKey().getPrivateKey();
	}
	
	/**
	 * @return the dataBundle of this user or {@code null} if the dataBundle was removed or this isn't a {@link #isNewDevice()}
	 */
	public DataBundle getTempDataBundle()
	{
		return dataBundle;
	}
	
	/**
	 * Sets the dataBundle of this user to {@code null}.
	 */
	public void removeTempDataBundle()
	{
		userStorage.finishedWithDataBundle();
		savedDataBundle = userStorage.getSavedDataBundle();
		dataBundle = null;
	}
	
	/**
	 * @return whether this device is a new device
	 */
	public boolean isNewDevice()
	{
		return newDevice;
	}
	
	/**
	 * @return a list of sessions used by this user
	 */
	public Map<UID, SessionsManager> getSessions()
	{
		return sessions;
	}
	
	/**
	 * @return the mac used by this user
	 */
	public Mac getMac()
	{
		return mac;
	}
	
	/**
	 * @return the cipher used by this user
	 */
	public MessengerCipher getCipher()
	{
		return cipher;
	}
}