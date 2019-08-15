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
package oughttoprevail.prevailprotocol.server;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;

import oughttoprevail.prevailprotocol.keys.IdentifiableKey;
import oughttoprevail.prevailprotocol.keys.ServerDataBundle;
import oughttoprevail.prevailprotocol.nonce.NonceGenerator;
import oughttoprevail.prevailprotocol.nonce.ServerNonceGenerator;
import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.Directory;
import oughttoprevail.prevailprotocol.storage.MailboxStorage;
import oughttoprevail.prevailprotocol.storage.Storage;
import oughttoprevail.prevailprotocol.storage.SynchronizedMailboxStorage;
import oughttoprevail.prevailprotocol.storage.fields.Field;
import oughttoprevail.prevailprotocol.storage.fields.JavaSerDes;
import oughttoprevail.prevailprotocol.uid.UID;
import oughttoprevail.prevailprotocol.uid.UserDeviceUID;

public class Server
{
	/**
	 * Server directory name
	 */
	private static final String SERVER_DIRECTORY = "Server";
	
	/**
	 * Directory for all server related storage
	 */
	private final Directory directory;
	/**
	 * Settings to use
	 */
	private final Settings settings;
	/**
	 * Whether this storage needs to be multi-threading compatible
	 */
	private final boolean multithreaded;
	/**
	 * Map for user identifier to server user storage
	 */
	private final Map<UID, ServerUserStorage> serverUserStorageMap;
	
	/**
	 * Constructs a new {@link Server}.
	 *
	 * @param settings to use
	 * @param multithreaded whether this storage should be multi-threading compatible
	 */
	public Server(Settings settings, boolean multithreaded)
	{
		this.directory = settings.getInitialDirectory().directory(SERVER_DIRECTORY);
		this.settings = settings;
		this.multithreaded = multithreaded;
		this.serverUserStorageMap = multithreaded ? new ConcurrentHashMap<>() : new HashMap<>();
	}
	
	/**
	 * Registers the specified parameters as a user's device.
	 *
	 * @param userDeviceUID identifier of the user's device
	 * @param identityKey is the public identity key
	 * @param signedPreKey is the public signed pre key
	 * @param preKeySignature is the pre key signature signed with the specified identityKey and the specified signedPreKey as the message
	 * @param oneTimePreKeys is the array of all initial public one time pre keys
	 */
	public boolean registerUserDevice(UserDeviceUID userDeviceUID,
									  byte[] identityKey,
									  IdentifiableKey signedPreKey,
									  byte[] preKeySignature,
									  IdentifiableKey[] oneTimePreKeys)
	{
		//verify
		if(!settings.getAsymmetricCryptography().verify(preKeySignature, signedPreKey.getKey(), identityKey))
		{
			return false;
		}
		ServerUserStorage serverUserStorage = getUserStorage(userDeviceUID.getUserId());
		serverUserStorage.deviceUIDs.add(userDeviceUID.getDeviceId());
		serverUserStorage.userStorage.flush();
		serverUserStorage.initializeDevice(userDeviceUID.getDeviceId()).init(identityKey, signedPreKey, preKeySignature, oneTimePreKeys);
		return true;
	}
	
	/**
	 * @param userId to get all registered data bundles for
	 * @return all the data bundles registered to the specified userId
	 */
	public List<ServerDataBundle> getDataBundles(UID userId)
	{
		List<ServerDataBundle> list = new ArrayList<>();
		Collection<ServerDevice> serverDevices = getUserStorage(userId).getDevices();
		for(ServerDevice serverDevice : serverDevices)
		{
			list.add(serverDevice.getServerDataBundle());
		}
		return list;
	}
	
	/**
	 * @param userDeviceUID of the data bundle
	 * @return whether a data bundle is registered for the specified userId and specified deviceId
	 */
	public boolean hasDataBundle(UserDeviceUID userDeviceUID)
	{
		return getDevice(userDeviceUID) != null;
	}
	
	/**
	 * Changes the signed pre key for the specified userId and specified deviceId to the specified signedPreKey, signedPreKeyUID and preKeySignature.
	 *
	 * @param userDeviceUID to change the signed pre key for
	 * @param signedPreKey to change to
	 * @param signedPreKeyUID identifier of the new signed pre key
	 * @param preKeySignature new signature of the signed pre key
	 * @return whether the pre key signature was successfully verified
	 * @throws IllegalArgumentException if a device with the specified userId and specified deviceId doesn't exist
	 */
	public boolean changeSignedPreKey(UserDeviceUID userDeviceUID, byte[] signedPreKey, UID signedPreKeyUID, byte[] preKeySignature)
	{
		ServerDevice device = getDevice(userDeviceUID);
		if(device == null)
		{
			throw new IllegalArgumentException("Device for " + userDeviceUID + " doesn't exist!");
		}
		ServerDataBundle serverDataBundle = device.getServerDataBundle();
		if(settings.getAsymmetricCryptography().verify(preKeySignature, signedPreKey, serverDataBundle.getIdentityKey()))
		{
			serverDataBundle.changeSignedPreKey(signedPreKey, signedPreKeyUID, preKeySignature);
			return true;
		}
		return false;
	}
	
	/**
	 * Adds the specified oneTimePreKeys to the one time pre keys list of {@link UserDeviceUID}.
	 *
	 * @param userDeviceUID to add the one time pre keys to
	 * @param oneTimePreKeys to add
	 */
	public void addOneTimePreKeys(UserDeviceUID userDeviceUID, List<IdentifiableKey> oneTimePreKeys)
	{
		ServerDevice device = getDevice(userDeviceUID);
		if(device != null)
		{
			device.getServerDataBundle().addOneTimePreKeys(oneTimePreKeys);
		}
	}
	
	/**
	 * @param userDeviceUID who's needed one time pre keys is to be returned
	 * @return the one time pre keys needed to have a full list of one time pre keys.
	 * By default this is {@code 0} but whenever a one time pre key is taken it grows, to fill the one time pre key invoke
	 * {@link #addOneTimePreKeys(UserDeviceUID, List)}.
	 * If {@link #addOneTimePreKeys(UserDeviceUID, List)} was invoked with a list larger then the needed, the result of this may be negative.
	 */
	public int getNeededOneTimePreKeys(UserDeviceUID userDeviceUID)
	{
		ServerDevice device = getDevice(userDeviceUID);
		if(device != null)
		{
			return settings.getDefaultTotalOneTimePreKeys() - device.getServerDataBundle().getTotalOneTimePreKeys();
		}
		return 0;
	}
	
	/**
	 * Adds the specified message to the mailbox of the specified userId and deviceId.
	 *
	 * @param userDeviceUID identifier of the mailbox
	 * @param message to add to the mailbox
	 */
	public void addMessage(UserDeviceUID userDeviceUID, byte[] message)
	{
		ServerDevice device = getDevice(userDeviceUID);
		if(device != null)
		{
			device.getMailbox().addMessage(message);
		}
	}
	
	/**
	 * @param userDeviceUID identifier of the mailbox
	 * @return all the messages stored in the mailbox with the specified identifiers
	 */
	public List<byte[]> retrieveMessages(UserDeviceUID userDeviceUID)
	{
		ServerDevice device = getDevice(userDeviceUID);
		if(device != null)
		{
			return device.getMailbox().getMessages();
		}
		return Collections.emptyList();
	}
	
	/**
	 * Removes the specified message from the mailbox.
	 *
	 * @param userDeviceUID identifier of the mailbox
	 * @param message to remove from the mailbox
	 */
	public void removeMessage(UserDeviceUID userDeviceUID, byte[] message)
	{
		ServerDevice device = getDevice(userDeviceUID);
		if(device != null)
		{
			device.getMailbox().removeMessage(message);
		}
	}
	
	/**
	 * Gets a previously created nonce or creates a new nonce and saves the nonce.
	 *
	 * @param userDeviceUID to create the nonce for
	 * @return the nonce, or {@code null} if a device with the specified userId and deviceId doesn't exist
	 */
	public byte[] getOrCreateNonce(UserDeviceUID userDeviceUID)
	{
		ServerDevice device = getDevice(userDeviceUID);
		if(device == null)
		{
			return null;
		}
		Nonce nonce = device.getNonce();
		byte[] nonceValue = nonce.get();
		if(nonceValue == null)
		{
			nonceValue = nonce.generateNonce();
		}
		return nonceValue;
	}
	
	/**
	 * @param userDeviceUID to verify signature for
	 * @param nonceSignature to verify
	 * @return {@code false} if saved information for the specified userDeviceUID can't be found, or if a nonce can't be found, or if the specified
	 * nonceSignature wasn't signed with the saved identity key or if the specified nonceSignature message isn't saved the saved nonce, else
	 * {@code true}
	 */
	public boolean verifyNonceSignature(UserDeviceUID userDeviceUID, byte[] nonceSignature)
	{
		ServerDevice device = getUserStorage(userDeviceUID.getUserId()).getDevice(userDeviceUID.getDeviceId());
		if(device == null)
		{
			return false;
		}
		byte[] nonce;
		if((nonce = device.getNonce().remove()) == null)
		{
			return false;
		}
		return settings.getAsymmetricCryptography().verify(nonceSignature, nonce, device.getServerDataBundle().getIdentityKey());
	}
	
	/**
	 * @param userId to get storage for
	 * @return the user storage for the specified userId
	 */
	private ServerUserStorage getUserStorage(UID userId)
	{
		ServerUserStorage serverUserStorage = serverUserStorageMap.get(userId);
		if(serverUserStorage == null)
		{
			serverUserStorageMap.put(userId, serverUserStorage = new ServerUserStorage(userId));
		}
		return serverUserStorage;
	}
	
	/**
	 * @param userDeviceUID of the device
	 * @return the {@link ServerDevice} of the specified userDeviceUID or {@code null} if there isn't one
	 */
	private ServerDevice getDevice(UserDeviceUID userDeviceUID)
	{
		return getUserStorage(userDeviceUID.getUserId()).getDevice(userDeviceUID.getDeviceId());
	}
	
	/**
	 * Server user storage manager
	 */
	private class ServerUserStorage
	{
		/**
		 * Device storage name
		 */
		private static final String DEVICE_STORAGE = "Device";
		
		/**
		 * Directory to save all user data in
		 */
		private final Directory userDirectory;
		/**
		 * User specific information storage
		 */
		private final Storage userStorage;
		/**
		 * List of devices belonging to this user
		 */
		private final List<UID> deviceUIDs;
		/**
		 * Map to access server device
		 */
		private final Map<UID, ServerDevice> deviceMap;
		
		/**
		 * Constructs a new {@link ServerUserStorage}.
		 *
		 * @param userId of the user
		 */
		private ServerUserStorage(UID userId)
		{
			String userIdString = userId.toString();
			userDirectory = directory.directory(userIdString);
			userStorage = userDirectory.storage(userIdString);
			
			List<UID> deviceUIDsList = userStorage.getFieldList(settings.getUIDFactory());
			deviceUIDs = multithreaded ? Collections.synchronizedList(deviceUIDsList) : deviceUIDsList;
			this.deviceMap = multithreaded ? new ConcurrentHashMap<>() : new HashMap<>();
			for(UID deviceId : deviceUIDs)
			{
				initializeDevice(deviceId);
			}
		}
		
		/**
		 * Initializes a stored {@link ServerDevice} for the specified deviceId.
		 *
		 * @param deviceId to initialize
		 * @return the {@link ServerDataBundle} for the specified deviceId
		 */
		private ServerDataBundle initializeDevice(UID deviceId)
		{
			Directory deviceDirectory = userDirectory.directory(deviceId.toString());
			Storage deviceStorage = deviceDirectory.storage(DEVICE_STORAGE);
			Field<byte[]> identityKeyField = deviceStorage.getField(JavaSerDes.BYTE_ARRAY_SER_DES);
			Field<IdentifiableKey> signedPreKeyField = deviceStorage.getField(IdentifiableKey.SER_DES);
			Field<byte[]> preKeySignatureField = deviceStorage.getField(JavaSerDes.BYTE_ARRAY_SER_DES);
			Queue<IdentifiableKey> oneTimePreKeysFields = deviceStorage.getFieldQueue(IdentifiableKey.SER_DES);
			ServerDataBundle serverDataBundle = new ServerDataBundle(deviceId,
					identityKeyField,
					signedPreKeyField,
					preKeySignatureField,
					oneTimePreKeysFields,
					deviceStorage);
			MailboxStorage mailbox = multithreaded ? new SynchronizedMailboxStorage(deviceDirectory) : new MailboxStorage(deviceDirectory);
			Nonce nonce = multithreaded ? new SynchronizedNonce(deviceStorage, settings) : new Nonce(deviceStorage, settings);
			deviceMap.put(deviceId, new ServerDevice(serverDataBundle, mailbox, nonce));
			return serverDataBundle;
		}
		
		/**
		 * @param deviceId of the device
		 * @return the device for the specified deviceId or {@code null} if there isn't a device with the specified deviceId
		 */
		private ServerDevice getDevice(UID deviceId)
		{
			return deviceMap.get(deviceId);
		}
		
		/**
		 * @return collection of all the known devices
		 */
		private Collection<ServerDevice> getDevices()
		{
			return deviceMap.values();
		}
	}
	
	/**
	 * Nonce manager
	 */
	private static class Nonce
	{
		/**
		 * A pending verification nonce
		 */
		private final Field<byte[]> pendingNonce;
		/**
		 * The storage to store the nonce in
		 */
		private final Storage deviceStorage;
		/**
		 * A nonce generator
		 */
		private final NonceGenerator generator;
		
		/**
		 * Constructs a new {@link Nonce}.
		 *
		 * @param deviceStorage to store the nonce in
		 * @param settings to use
		 */
		private Nonce(Storage deviceStorage, Settings settings)
		{
			this.pendingNonce = deviceStorage.getField(JavaSerDes.BYTE_ARRAY_SER_DES);
			this.deviceStorage = deviceStorage;
			this.generator = new ServerNonceGenerator(deviceStorage, settings);
		}
		
		/**
		 * Generates a nonce and saves it
		 *
		 * @return the generated nonce
		 */
		byte[] generateNonce()
		{
			byte[] nonce;
			set(nonce = generator.generateNonce());
			return nonce;
		}
		
		/**
		 * @return the pending nonce value or {@code null} if there isn't a pending nonce
		 */
		byte[] get()
		{
			return pendingNonce.get();
		}
		
		/**
		 * Gets then removes from storage the current pending nonce value
		 *
		 * @return the pending nonce value before it was removed from storage
		 */
		byte[] remove()
		{
			byte[] nonce = get();
			set(null);
			return nonce;
		}
		
		/**
		 * Sets the pending nonce to the specified nonce
		 *
		 * @param nonce to set
		 */
		private void set(byte[] nonce)
		{
			pendingNonce.set(nonce);
			deviceStorage.flush();
		}
	}
	
	/**
	 * A synchronized, multi-threaded supported nonce
	 */
	private static class SynchronizedNonce extends Nonce
	{
		/**
		 * Equals to {@link Nonce#Nonce(Storage, Settings)}
		 */
		private SynchronizedNonce(Storage deviceStorage, Settings settings)
		{
			super(deviceStorage, settings);
		}
		
		/**
		 * {@inheritDoc}
		 */
		@Override
		synchronized byte[] generateNonce()
		{
			return super.generateNonce();
		}
		
		/**
		 * {@inheritDoc}
		 */
		@Override
		synchronized byte[] get()
		{
			return super.get();
		}
		
		/**
		 * {@inheritDoc}
		 */
		@Override
		synchronized byte[] remove()
		{
			return super.remove();
		}
	}
	
	/**
	 * A server device manager
	 */
	private static class ServerDevice
	{
		/**
		 * Device public data bundle
		 */
		private final ServerDataBundle serverDataBundle;
		/**
		 * Mailbox of the device, pending messages which need to be sent to it will go here
		 */
		private final MailboxStorage mailbox;
		/**
		 * Nonce manager of this device
		 */
		private final Nonce nonce;
		
		/**
		 * Constructs a new {@link ServerDevice}.
		 */
		private ServerDevice(ServerDataBundle serverDataBundle, MailboxStorage mailbox, Nonce nonce)
		{
			this.mailbox = mailbox;
			this.serverDataBundle = serverDataBundle;
			this.nonce = nonce;
		}
		
		private ServerDataBundle getServerDataBundle()
		{
			return serverDataBundle;
		}
		
		private MailboxStorage getMailbox()
		{
			return mailbox;
		}
		
		private Nonce getNonce()
		{
			return nonce;
		}
	}
}