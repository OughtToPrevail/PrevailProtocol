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
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import oughttoprevail.prevailprotocol.exception.CounterTooLargeException;
import oughttoprevail.prevailprotocol.exception.MissingMatchingHeaderKeyException;
import oughttoprevail.prevailprotocol.exception.MissingSkippedKeyException;
import oughttoprevail.prevailprotocol.exception.TooManyDevicesException;
import oughttoprevail.prevailprotocol.exception.VerificationFailedException;
import oughttoprevail.prevailprotocol.keys.DataBundle;
import oughttoprevail.prevailprotocol.keys.IdentifiableKey;
import oughttoprevail.prevailprotocol.keys.IdentifiableKeyPair;
import oughttoprevail.prevailprotocol.keys.SignedPreKey;
import oughttoprevail.prevailprotocol.messenger.Messenger;
import oughttoprevail.prevailprotocol.session.Session;
import oughttoprevail.prevailprotocol.uid.StringWrapper;
import oughttoprevail.prevailprotocol.uid.UID;

public class HelloWorldSend
{
	@Test
	public void helloWorldSend() throws NoSuchAlgorithmException, VerificationFailedException, InvalidKeyException, TooManyDevicesException,
										InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException,
										MissingSkippedKeyException, CounterTooLargeException, MissingMatchingHeaderKeyException,
										NoSuchPaddingException
	{
		//first create user identifiers
		UID aliceUserId = new StringWrapper("Alice");
		UID bobUserId = new StringWrapper("Bob");
		
		//create users
		User alice = new User(aliceUserId);
		User bob = new User(bobUserId);
		
		//Since we don't have a Server in this example and Alice is only registering and not being registered just remove the data bundle.
		alice.removeTempDataBundle();
		
		//get Bob's data bundle
		DataBundle tempDataBundle = bob.getTempDataBundle();
		//since we now have Bob's data bundle we can remove it
		bob.removeTempDataBundle();
		
		byte[] identityPublicKey = tempDataBundle.getIdentityKeys().getPublicKey();
		SignedPreKey signedPreKey = tempDataBundle.getSignedPreKey();
		IdentifiableKeyPair oneTimePreKey = tempDataBundle.getOneTimePreKeys()[0];
		
		IdentifiableKey publicSignedPreKey = new IdentifiableKey(signedPreKey.getUID(), signedPreKey.getPublicKey());
		byte[] preKeySignature = signedPreKey.getPreKeySignature();
		IdentifiableKey publicOneTimePreKey = new IdentifiableKey(oneTimePreKey.getUID(), oneTimePreKey.getPublicKey());
		
		Session session = alice.aliceRegister(bob.getUserDeviceUID(), identityPublicKey, publicSignedPreKey, preKeySignature, publicOneTimePreKey);
		
		Messenger messenger = session.getMessenger();
		byte[] message = "Hello World".getBytes();
		
		byte[] encryptedMessage = messenger.encryptMessage(message);
		
		Messenger bobMessenger = bob.getMessenger(alice.getUserDeviceUID());
		byte[] decryptMessage = bobMessenger.decryptMessage(encryptedMessage);
		Assert.assertArrayEquals(decryptMessage, message);
	}
}