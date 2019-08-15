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

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.VerboseMode;

import oughttoprevail.prevailprotocol.keys.DataBundle;
import oughttoprevail.prevailprotocol.keys.IdentifiableKey;
import oughttoprevail.prevailprotocol.keys.IdentifiableKeyPair;
import oughttoprevail.prevailprotocol.keys.SignedPreKey;
import oughttoprevail.prevailprotocol.messenger.EncryptedMessage;
import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.Directory;
import oughttoprevail.prevailprotocol.uid.StringWrapper;
import oughttoprevail.prevailprotocol.uid.UID;

public class BenchmarkTest
{
	public static void main(String[] args) throws RunnerException
	{
		new Runner(new OptionsBuilder().include(BenchmarkTest.class.getSimpleName())
									   .verbosity(VerboseMode.EXTRA)
									   .warmupIterations(5)
									   .measurementIterations(3)
									   .forks(5)
									   .build()).run();
	}
	
	private static final UID ALICE_USER_ID = new StringWrapper("Alice");
	private static final UID BOB_USER_ID = new StringWrapper("Bob");
	
	private static final Settings SETTINGS = Settings.create().initialDirectory(Directory.newInMemoryDirectory()).defaultTotalOneTimePreKeys(1);
	
	private static final byte[] ORIGINAL_MESSAGE_BYTES = "Hello World".getBytes();
	
	@Benchmark
	public void test(Blackhole blackhole) throws Exception
	{
		User alice = new User(ALICE_USER_ID, SETTINGS);
		User bob = new User(BOB_USER_ID, SETTINGS);
		alice.removeTempDataBundle();
		
		DataBundle tempDataBundle = bob.getTempDataBundle();
		bob.removeTempDataBundle();
		SignedPreKey signedPreKeys = tempDataBundle.getSignedPreKey();
		IdentifiableKeyPair oneTimePreKey = tempDataBundle.getOneTimePreKeys()[0];
		alice.aliceRegister(bob.getUserDeviceUID(),
				tempDataBundle.getIdentityKeys().getPublicKey(),
				new IdentifiableKey(signedPreKeys.getUID(), signedPreKeys.getPublicKey()),
				signedPreKeys.getPreKeySignature(),
				new IdentifiableKey(oneTimePreKey.getUID(), oneTimePreKey.getPublicKey()));
		
		EncryptedMessage[] encrypted = alice.encryptMessage(BOB_USER_ID, ORIGINAL_MESSAGE_BYTES, false);
		for(EncryptedMessage message : encrypted)
		{
			byte[] plaintext = bob.getMessenger(alice.getUserDeviceUID()).decryptMessage(message.getEncryptedMessage());
			blackhole.consume(plaintext);
			blackhole.consume(message);
		}
		blackhole.consume(encrypted);
		encrypted = bob.encryptMessage(ALICE_USER_ID, ORIGINAL_MESSAGE_BYTES, false);
		for(EncryptedMessage message : encrypted)
		{
			byte[] plaintext = alice.getMessenger(bob.getUserDeviceUID()).decryptMessage(message.getEncryptedMessage());
			blackhole.consume(plaintext);
			blackhole.consume(message);
		}
		blackhole.consume(encrypted);
		blackhole.consume(alice);
		blackhole.consume(bob);
		blackhole.consume(tempDataBundle);
		blackhole.consume(signedPreKeys);
		blackhole.consume(oneTimePreKey);
	}
}