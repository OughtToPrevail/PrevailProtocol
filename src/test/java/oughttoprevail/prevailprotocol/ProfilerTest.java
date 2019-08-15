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

import org.junit.Assert;

import oughttoprevail.prevailprotocol.keys.DataBundle;
import oughttoprevail.prevailprotocol.keys.IdentifiableKey;
import oughttoprevail.prevailprotocol.keys.IdentifiableKeyPair;
import oughttoprevail.prevailprotocol.keys.SignedPreKey;
import oughttoprevail.prevailprotocol.messenger.EncryptedMessage;
import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.Directory;
import oughttoprevail.prevailprotocol.uid.StringWrapper;
import oughttoprevail.prevailprotocol.uid.UID;

public class ProfilerTest
{
	public static void main(String[] args) throws Exception
	{
		Settings settings = Settings.create().initialDirectory(Directory.newInMemoryDirectory()).defaultTotalOneTimePreKeys(1);
		UID aliceUserId = new StringWrapper("Alice");
		UID bobUserId = new StringWrapper("Bob");
		
		User alice = new User(aliceUserId, settings);
		User bob = new User(bobUserId, settings);
		alice.removeTempDataBundle();
		
		DataBundle tempDataBundle = bob.getTempDataBundle();
		bob.removeTempDataBundle();
		SignedPreKey signedPreKeys = tempDataBundle.getSignedPreKey();
		IdentifiableKeyPair oneTimePreKey = tempDataBundle.getOneTimePreKeys()[0];
		alice.aliceRegister(bob.getUserDeviceUID(),
				bob.getIdentityPublicKey(),
				new IdentifiableKey(signedPreKeys.getUID(), signedPreKeys.getPublicKey()),
				signedPreKeys.getPreKeySignature(),
				new IdentifiableKey(oneTimePreKey.getUID(), oneTimePreKey.getPublicKey()));
		
		for(int i = 0; i < 100; i++)
		{
			String originalMessage = "Hello World!";
			byte[] originalMessageBytes = originalMessage.getBytes();
			
			EncryptedMessage[] encrypted = alice.encryptMessage(bobUserId, originalMessageBytes, false);
			for(EncryptedMessage message : encrypted)
			{
				byte[] plaintext = bob.getMessenger(alice.getUserDeviceUID()).decryptMessage(message.getEncryptedMessage());
				Assert.assertArrayEquals(plaintext, originalMessageBytes);
			}
			encrypted = bob.encryptMessage(aliceUserId, originalMessageBytes, false);
			for(EncryptedMessage message : encrypted)
			{
				byte[] plaintext = alice.getMessenger(bob.getUserDeviceUID()).decryptMessage(message.getEncryptedMessage());
				Assert.assertArrayEquals(plaintext, originalMessageBytes);
			}
		}
	}
}