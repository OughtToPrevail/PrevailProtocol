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

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import oughttoprevail.prevailprotocol.exception.NotMainDirectoryException;
import oughttoprevail.prevailprotocol.fingerprint.FingerprintHandler;
import oughttoprevail.prevailprotocol.group.EncryptedGroupMessage;
import oughttoprevail.prevailprotocol.group.Group;
import oughttoprevail.prevailprotocol.keys.DataBundle;
import oughttoprevail.prevailprotocol.keys.IdentifiableKey;
import oughttoprevail.prevailprotocol.keys.IdentifiableKeyPair;
import oughttoprevail.prevailprotocol.keys.ServerDataBundle;
import oughttoprevail.prevailprotocol.keys.SignedPreKey;
import oughttoprevail.prevailprotocol.messenger.EncryptedMessage;
import oughttoprevail.prevailprotocol.messenger.Messenger;
import oughttoprevail.prevailprotocol.server.Server;
import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.uid.StringWrapper;
import oughttoprevail.prevailprotocol.uid.UID;
import oughttoprevail.prevailprotocol.uid.UserDeviceUID;

/**
 * Test for most operations
 * Notes:
 * 1. If the second run doesn't work it most likely means there is a problem with storage.
 * 2. It is recommended to try to change the {@link Settings} if you'd like to change if they work
 */
public class Test
{
	private static final byte[] MESSAGE_BYTES = "Hello World!".getBytes();
	private static Server server;
	private static User alice;
	private static User bob;
	private static UserDeviceUID aliceId;
	private static UserDeviceUID bobId;
	private static UID groupId;
	
	@BeforeClass
	public static void beforeTest() throws Exception
	{
		UID aliceUserId = new StringWrapper("Alice");
		UID bobUserId = new StringWrapper("Bob");
		
		Settings settings = Settings.getDefaultSettings();
		
		alice = new User(aliceUserId, settings);
		aliceId = alice.getUserDeviceUID();
		
		bob = new User(bobUserId, settings);
		bobId = bob.getUserDeviceUID();
		
		groupId = new StringWrapper("GroupId");
		
		server = new Server(settings, false);
		
		registerOrVerify(alice);
		registerOrVerify(bob);
		
		//X3DH
		boolean aliceRegister = !alice.hasSession(bobId);
		boolean bobRegister = !bob.hasSession(aliceId);
		
		System.out.println("HAS SESSION " + aliceRegister + " " + bobRegister);
		
		if(aliceRegister || bobRegister)
		{
			List<ServerDataBundle> bobDataBundles = server.getDataBundles(bob.getUserDeviceUID().getUserId());
			for(ServerDataBundle bobDataBundle : bobDataBundles)
			{
				alice.aliceRegister(bobId,
						bobDataBundle.getIdentityKey(),
						bobDataBundle.getSignedPreKey(),
						bobDataBundle.getPreKeySignature(),
						bobDataBundle.pickOneTimePreKey());
			}
		}
	}
	
	private static void registerOrVerify(User user)
	{
		if(user.isNewDevice())
		{
			DataBundle dataBundle = user.getTempDataBundle();
			SignedPreKey signedPreKey = dataBundle.getSignedPreKey();
			IdentifiableKeyPair[] oneTimePreKeys = dataBundle.getOneTimePreKeys();
			IdentifiableKey[] serverOneTimePreKeys = new IdentifiableKey[oneTimePreKeys.length];
			for(int i = 0; i < oneTimePreKeys.length; i++)
			{
				IdentifiableKeyPair oneTimePreKey = oneTimePreKeys[i];
				serverOneTimePreKeys[i] = new IdentifiableKey(oneTimePreKey.getUID(), oneTimePreKey.getPublicKey());
			}
			user.removeTempDataBundle();
			if(!server.registerUserDevice(user.getUserDeviceUID(),
					dataBundle.getIdentityKeys().getPublicKey(),
					new IdentifiableKey(signedPreKey.getUID(), signedPreKey.getPublicKey()),
					signedPreKey.getPreKeySignature(),
					serverOneTimePreKeys))
			{
				throw new IllegalStateException(String.format("Failed register for %s!", user.getUserDeviceUID().toString()));
			}
		} else
		{
			byte[] nonce = server.getOrCreateNonce(user.getUserDeviceUID());
			byte[] nonceSignature = user.signNonce(nonce);
			if(!server.verifyNonceSignature(user.getUserDeviceUID(), nonceSignature))
			{
				throw new IllegalStateException(String.format("Failed nonce verification for %s ! (Nonce signature: %s)",
						user.getUserDeviceUID().toString(),
						Arrays.toString(nonceSignature)));
			}
		}
	}
	
	@AfterClass
	public static void end()
	{
		try
		{
			Settings.getDefaultSettings().getInitialDirectory().finish();
		} catch(NotMainDirectoryException e)
		{
			e.printStackTrace();
		}
	}
	
	@org.junit.Test
	public void simplePairwise() throws Exception
	{
		pairwiseTest(1, false);
	}
	
	@org.junit.Test
	public void repeatPairwise() throws Exception
	{
		pairwiseTest(10, false);
	}
	
	@org.junit.Test
	public void shufflePairwise() throws Exception
	{
		pairwiseTest(1, true);
	}
	
	@org.junit.Test
	public void repeatAndShufflePairwise() throws Exception
	{
		pairwiseTest(10, true);
	}
	
	@org.junit.Test
	public void repeatedPairwiseTest() throws Exception
	{
		for(int i = 0; i < 100; i++)
		{
			repeatAndShufflePairwise();
		}
	}
	
	private void pairwiseTest(int repeatTimes, boolean shuffle) throws Exception
	{
		encryptThenDecrypt(alice, bob, repeatTimes, shuffle);
		encryptThenDecrypt(bob, alice, repeatTimes, shuffle);
	}
	
	private void encryptThenDecrypt(User sender, User receiver, int repeatTimes, boolean shuffle) throws Exception
	{
		List<EncryptedMessage> encryptedMessages = new ArrayList<>();
		for(int i = 0; i < repeatTimes; i++)
		{
			Collections.addAll(encryptedMessages, sender.encryptMessage(receiver.getUserDeviceUID().getUserId(), MESSAGE_BYTES));
		}
		if(shuffle)
		{
			Collections.shuffle(encryptedMessages);
		}
		EncryptedMessage[] array = encryptedMessages.toArray(new EncryptedMessage[0]);
		
		Messenger messenger = receiver.getMessenger(sender.getUserDeviceUID());
		for(EncryptedMessage encryptedMessage : array)
		{
			byte[] decrypted = messenger.decryptMessage(encryptedMessage.getEncryptedMessage());
			Assert.assertArrayEquals(decrypted, MESSAGE_BYTES);
		}
	}
	
	@org.junit.Test
	public void simpleGroup() throws Exception
	{
		groupTest(1, false);
	}
	
	@org.junit.Test
	public void repeatGroup() throws Exception
	{
		groupTest(10, false);
	}
	
	@org.junit.Test
	public void shuffleGroup() throws Exception
	{
		groupTest(1, true);
	}
	
	@org.junit.Test
	public void repeatAndShuffleGroup() throws Exception
	{
		groupTest(10, true);
	}
	
	@org.junit.Test
	public void repeatedGroupTest() throws Exception
	{
		for(int i = 0; i < 100; i++)
		{
			repeatAndShuffleGroup();
		}
	}
	
	private void groupTest(int repeatTimes, boolean shuffle) throws Exception
	{
		encryptThenDecryptGroup(alice, bob, repeatTimes, shuffle);
		encryptThenDecryptGroup(bob, alice, repeatTimes, shuffle);
	}
	
	private void encryptThenDecryptGroup(User sender, User receiver, int repeatTimes, boolean shuffle) throws Exception
	{
		Group senderGroup = sender.getOrCreateGroup(groupId);
		Group receiverGroup = receiver.getOrCreateGroup(groupId);
		
		maybeJoinMember(sender, receiver, senderGroup, receiverGroup);
		maybeJoinMember(receiver, sender, receiverGroup, senderGroup);
		
		List<EncryptedGroupMessage> encryptedGroupMessages = new ArrayList<>();
		for(int i = 0; i < repeatTimes; i++)
		{
			EncryptedGroupMessage encryptedGroupMessage = senderGroup.encryptMessage(MESSAGE_BYTES);
			encryptedGroupMessages.add(encryptedGroupMessage);
		}
		if(shuffle)
		{
			Collections.shuffle(encryptedGroupMessages);
		}
		EncryptedGroupMessage[] groupMessages = encryptedGroupMessages.toArray(new EncryptedGroupMessage[0]);
		for(EncryptedGroupMessage encryptedGroupMessage : groupMessages)
		{
			byte[] decryptedMessage = receiverGroup.decryptMessage(sender.getUserDeviceUID(), encryptedGroupMessage.getCiphertext());
			Assert.assertArrayEquals(MESSAGE_BYTES, decryptedMessage);
		}
	}
	
	private void maybeJoinMember(User joining, User user, Group joiningGroup, Group group) throws Exception
	{
		UserDeviceUID userDeviceUID = user.getUserDeviceUID();
		UserDeviceUID joiningUserDeviceUID = joining.getUserDeviceUID();
		
		if(!group.hasMember(joiningUserDeviceUID))
		{
			byte[] encryptedSenderKey = joiningGroup.encryptSenderKey(userDeviceUID);
			byte[] senderKey = user.getMessenger(joiningUserDeviceUID).decryptMessage(encryptedSenderKey);
			
			group.memberJoined(joiningUserDeviceUID, senderKey);
		}
	}
	
	@org.junit.Test
	public void fingerprintTest() throws Exception
	{
		FingerprintHandler aliceFingerprintHandler = alice.getOrCreateFingerprintHandler();
		FingerprintHandler bobFingerprintHandler = bob.getOrCreateFingerprintHandler();
		aliceFingerprintHandler.onFingerprintChange(userId -> System.out.println("FINGER PRINT CHANGED FOR " +
																				 alice +
																				 ", finger print changed: " +
																				 userId));
		bobFingerprintHandler.onFingerprintChange(userId -> System.out.println("FINGER PRINT CHANGED FOR " +
																			   bob +
																			   ", finger print changed: " +
																			   userId));
		
		UID aliceUserId = aliceId.getUserId();
		UID bobUserId = bobId.getUserId();
		
		byte[] aliceFingerprint = aliceFingerprintHandler.getMyFingerprint();
		byte[] bobFingerprint = bobFingerprintHandler.getMyFingerprint();
		byte[] whatAliceThinksIsBobFingerprint = aliceFingerprintHandler.getFingerprint(bobUserId);
		byte[] whatBobThinksIsAliceFingerprint = bobFingerprintHandler.getFingerprint(aliceUserId);
		
		System.out.println("FINGERPRINTS \n" +
						   Arrays.toString(aliceFingerprint) +
						   "\n" +
						   Arrays.toString(bobFingerprint) +
						   "\n" +
						   Arrays.toString(whatAliceThinksIsBobFingerprint) +
						   "\n" +
						   Arrays.toString(whatBobThinksIsAliceFingerprint));
		
		Assert.assertTrue(aliceFingerprintHandler.compareFingerprints(bobUserId, bobFingerprint, whatBobThinksIsAliceFingerprint));
		Assert.assertTrue(bobFingerprintHandler.compareFingerprints(aliceUserId, aliceFingerprint, whatAliceThinksIsBobFingerprint));
	}
}